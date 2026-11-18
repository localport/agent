package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/proto"
	"github.com/localport/agent/internal/transport"
)

// The wait of a hinted refusal is at least the hint (capped at 5 min) and
// below the hint plus the backoff, which doubles from 30 s up to 5 min.
func TestRefusalWaitBounds(t *testing.T) {
	for n := 1; n <= 8; n++ {
		backoff := min(maxRefusalWait, refusalBackoffBase<<min(n-1, 4))
		for _, hint := range []time.Duration{0, time.Minute, 10 * time.Minute} {
			floor := min(hint, maxRefusalWait)
			for range 200 {
				if d := refusalWait(hint, n); d < floor || d >= floor+backoff {
					t.Fatalf("refusalWait(%v, %d) = %v, want in [%v, %v)", hint, n, d, floor, floor+backoff)
				}
			}
		}
	}
}

// refusalRun is a tunnel whose Run the test drives as the edge: each dial
// hands the edge side over, and each hinted wait is recorded and ends at once.
type refusalRun struct {
	tn     *Tunnel
	dialer *pipeDialer
	waits  chan time.Duration

	mu       sync.Mutex
	statuses []Status
	result   chan error
}

func startRefusalRun(t *testing.T, opts Options, setup ...func(*Tunnel)) *refusalRun {
	t.Helper()
	r := &refusalRun{dialer: &pipeDialer{edges: make(chan net.Conn, 1)}, waits: make(chan time.Duration, 8), result: make(chan error, 1)}
	opts.Edge = "connect.eu.localport.dev:443"
	opts.OnStatus = func(st Status) {
		r.mu.Lock()
		r.statuses = append(r.statuses, st)
		r.mu.Unlock()
	}
	r.tn = New(opts)
	r.tn.newDialers = func(transport.Options) []transport.Dialer { return []transport.Dialer{r.dialer} }
	r.tn.after = func(d time.Duration) <-chan time.Time {
		r.waits <- d
		ch := make(chan time.Time, 1)
		ch <- time.Now()
		return ch
	}
	for _, f := range setup {
		f(r.tn)
	}
	go func() { r.result <- r.tn.Run(context.Background()) }()
	t.Cleanup(func() {
		r.tn.Stop()
		select {
		case <-r.result:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after Stop")
		}
	})
	return r
}

// register plays the edge for one dial: it reads the Register and answers ack.
func (r *refusalRun) register(t *testing.T, ack proto.RegisterAckPayload) *fakeEdge {
	t.Helper()
	var edgeSide net.Conn
	select {
	case edgeSide = <-r.dialer.edges:
	case <-time.After(3 * time.Second):
		t.Fatal("the tunnel did not dial")
	}
	t.Cleanup(func() { edgeSide.Close() })
	edge := &fakeEdge{conn: proto.NewConn(edgeSide)}
	edge.expect(t, proto.MsgRegister)
	edge.send(t, proto.MsgRegisterAck, ack)
	return edge
}

func (r *refusalRun) nextWait(t *testing.T) time.Duration {
	t.Helper()
	select {
	case d := <-r.waits:
		return d
	case <-time.After(3 * time.Second):
		t.Fatal("no hinted wait")
		return 0
	}
}

// sawWaiting reports whether the tunnel published StateWaiting with code.
func (r *refusalRun) sawWaiting(code string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, st := range r.statuses {
		if st.State == StateWaiting && st.Code == code && !st.NextRetry.IsZero() {
			return true
		}
	}
	return false
}

func (r *refusalRun) sawState(s State) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, st := range r.statuses {
		if st.State == s {
			return true
		}
	}
	return false
}

// A device refused with a retry_after hint keeps retrying, waiting at least
// the hint and publishing the code, and runs once a registration is
// accepted; it never reports the refusal to its credential and never ends.
func TestHintedRefusalKeepsADeviceRetrying(t *testing.T) {
	cred := &fakeCredential{presentation: &identity.Presentation{Serial: "aa"}}
	r := startRefusalRun(t, Options{Kind: proto.KindDevice, Credential: cred, DisableMux: true})

	r.register(t, proto.RegisterAckPayload{Error: "plan is paused", ErrorCode: "BL012", Retryable: boolPtr(false), RetryAfter: 60})
	if d := r.nextWait(t); d < time.Minute || d >= time.Minute+refusalBackoffBase {
		t.Fatalf("first wait %v, want the 60 s hint plus under 30 s", d)
	}
	if !r.sawWaiting("BL012") {
		t.Fatal("the tunnel did not publish waiting with BL012")
	}
	r.register(t, proto.RegisterAckPayload{Success: true, SessionID: "s1"})
	for deadline := time.Now().Add(3 * time.Second); !r.sawState(StateActive); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the tunnel did not run after the refusal lifted")
		}
	}
	if _, refused := cred.counts(); refused != 0 {
		t.Fatalf("a hinted refusal reached the credential %d times", refused)
	}
	select {
	case err := <-r.result:
		t.Fatalf("Run returned %v on a hinted refusal", err)
	default:
	}
}

// An interactive tunnel prints a hinted non-retryable refusal and exits.
func TestHintedRefusalEndsAnInteractiveTunnel(t *testing.T) {
	r := startRefusalRun(t, Options{Kind: proto.KindTunnel, Token: "tok", Local: "127.0.0.1:1"})
	r.register(t, proto.RegisterAckPayload{Error: "plan is paused", ErrorCode: "BL012", Retryable: boolPtr(false), RetryAfter: 60})
	select {
	case err := <-r.result:
		var regErr *RegistrationError
		if !errors.As(err, &regErr) || regErr.Code != "BL012" {
			t.Fatalf("Run = %v, want the BL012 refusal", err)
		}
		r.result <- err // for the cleanup
	case <-time.After(3 * time.Second):
		t.Fatal("an interactive tunnel kept retrying a hinted refusal")
	}
}

// A device refused for good without a hint ends with the refusal and the
// serial of the certificate it presented, for the runner to park or forget.
func TestUnhintedRefusalEndsADeviceWithTheSerial(t *testing.T) {
	cred := &fakeCredential{presentation: &identity.Presentation{Serial: "aa"}}
	r := startRefusalRun(t, Options{Kind: proto.KindDevice, Credential: cred})
	r.register(t, proto.RegisterAckPayload{Error: "not on the fleet", ErrorCode: "SE018", Retryable: boolPtr(false)})
	select {
	case err := <-r.result:
		var regErr *RegistrationError
		if !errors.As(err, &regErr) || regErr.Code != "SE018" || regErr.Serial != "aa" {
			t.Fatalf("Run = %#v, want SE018 with serial aa", err)
		}
		r.result <- err
	case <-time.After(3 * time.Second):
		t.Fatal("a device kept retrying an unhinted refusal")
	}
}

// A removal Shutdown (SE041, no hint) ends the device with the serial of the
// certificate the session registered with, so the runner can forget it.
func TestRemovalShutdownEndsADeviceWithTheSerial(t *testing.T) {
	cred := &fakeCredential{presentation: &identity.Presentation{Serial: "bb"}}
	r := startRefusalRun(t, Options{Kind: proto.KindDevice, Credential: cred, DisableMux: true})
	edge := r.register(t, proto.RegisterAckPayload{Success: true, SessionID: "s1"})
	_ = edge.conn.SetReadDeadline(time.Time{})
	go func() {
		for {
			if _, _, err := edge.conn.Recv(); err != nil {
				return
			}
		}
	}()
	edge.send(t, proto.MsgShutdown, proto.ShutdownPayload{Reason: "revoked", Code: "SE041", Retryable: boolPtr(false)})
	select {
	case err := <-r.result:
		var regErr *RegistrationError
		if !errors.As(err, &regErr) || regErr.Code != "SE041" || regErr.Serial != "bb" {
			t.Fatalf("Run = %#v, want SE041 with serial bb", err)
		}
		r.result <- err
	case <-time.After(5 * time.Second):
		t.Fatal("a removal Shutdown did not end the device")
	}
}

// An admin's Disconnect (SE040 Shutdown with the hint) drains the session,
// then the device waits as for a hinted refusal and registers again.
func TestDisconnectShutdownDrainsThenWaits(t *testing.T) {
	cred := &fakeCredential{presentation: &identity.Presentation{Serial: "aa"}}
	// No port mux: its bind dial would take the next registration's pipe.
	r := startRefusalRun(t, Options{Kind: proto.KindDevice, Credential: cred, DisableMux: true})
	edge := r.register(t, proto.RegisterAckPayload{Success: true, SessionID: "s1"})
	// Read what the agent sends (heartbeats) so its writes never block.
	_ = edge.conn.SetReadDeadline(time.Time{})
	go func() {
		for {
			if _, _, err := edge.conn.Recv(); err != nil {
				return
			}
		}
	}()
	edge.send(t, proto.MsgShutdown, proto.ShutdownPayload{Reason: "disconnected", Code: "SE040", Retryable: boolPtr(true), RetryAfter: 60})
	r.nextWait(t)
	if !r.sawState(StateDraining) || !r.sawWaiting("SE040") {
		t.Fatal("the device did not drain, then wait with SE040")
	}
	r.register(t, proto.RegisterAckPayload{Success: true, SessionID: "s2"})
}

// drain ends the handler's sessions before the recordings flush runs, and
// stop does not shut the handler down again.
func TestSessionMuxDrainOrder(t *testing.T) {
	edge := newFakeSessionEdge(t)
	d := &pipeSessionDial{edge: edge}
	h := newStreamEchoHandler()
	m := newSessionMux(context.Background(), "test", h, d.dial)
	m.start()
	edge.expectAccept(t)

	var shutdownsAtFlush int32 = -1
	m.drain(t.Context(), func(context.Context) {
		shutdownsAtFlush = h.shutdownCalls.Load()
	})
	if shutdownsAtFlush != 1 {
		t.Fatalf("Shutdown calls when the flush ran = %d, want 1", shutdownsAtFlush)
	}
	m.stop()
	if n := h.shutdownCalls.Load(); n != 1 {
		t.Fatalf("Shutdown ran %d times after drain and stop, want 1", n)
	}
}

// A drain's recordings flush is bounded and ends when the tunnel stops.
func TestDrainSessionsEndsOnStop(t *testing.T) {
	edge := newFakeSessionEdge(t)
	d := &pipeSessionDial{edge: edge}
	m := newSessionMux(context.Background(), "test", newStreamEchoHandler(), d.dial)
	m.start()
	edge.expectAccept(t)
	defer m.stop()

	flushing := make(chan struct{})
	tn := New(Options{Kind: proto.KindDevice, FlushRecordings: func(ctx context.Context) {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("the flush runs without a bound")
		}
		close(flushing)
		<-ctx.Done()
	}})
	tn.sessionMux.Store(m)
	done := make(chan struct{})
	go func() {
		tn.drainSessions(t.Context())
		close(done)
	}()
	<-flushing
	tn.Stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the drain outlived Stop")
	}
}

// Entering a wait notifies OnStatus once; a repeated wait notifies again.
func TestSetWaitingNotifiesOncePerChange(t *testing.T) {
	var notified int
	tn := New(Options{Kind: proto.KindDevice, OnStatus: func(Status) { notified++ }})
	tn.setWaiting("SE040", time.Now())
	if notified != 1 {
		t.Fatalf("entering a wait notified %d times, want 1", notified)
	}
	tn.setWaiting("SE040", time.Now().Add(time.Minute))
	if notified != 2 {
		t.Fatalf("a repeated wait notified %d times in all, want 2", notified)
	}
}

// A hinted Shutdown read by the reader of an ended session neither records a
// kick nor ends the current session; one of the current session does both.
func TestKickFromAnEndedSessionIsIgnored(t *testing.T) {
	tn := New(Options{Kind: proto.KindDevice})
	ended := make(chan struct{})
	tn.mu.Lock()
	current := make(chan struct{})
	tn.disconnected = current
	tn.mu.Unlock()

	cause := errors.New("the edge ended the session: disconnected [SE040]")
	tn.kickSession(&kick{code: "SE040", drain: true}, ended, cause)
	if tn.kicked.Load() != nil || tn.endCause != nil {
		t.Fatal("an ended session's Shutdown recorded a kick or a cause")
	}
	select {
	case <-current:
		t.Fatal("an ended session's Shutdown ended the current session")
	default:
	}

	tn.kickSession(&kick{code: "SE040", drain: true}, current, cause)
	if tn.kicked.Load() == nil || tn.endCause != cause {
		t.Fatalf("the current session's Shutdown recorded kick %v, cause %v; want the kick and %v", tn.kicked.Load(), tn.endCause, cause)
	}
	select {
	case <-current:
	default:
		t.Fatal("the current session's Shutdown did not end it")
	}
}

// While a device drains for an admin's Disconnect it keeps reading the
// control connection: a terminal Shutdown (a teardown during the drain) ends
// the drain at once and is returned; a hinted one is dropped.
func TestDrainReadingControlEndsOnATerminalShutdown(t *testing.T) {
	sessEdge := newFakeSessionEdge(t)
	d := &pipeSessionDial{edge: sessEdge}
	m := newSessionMux(context.Background(), "test", newStreamEchoHandler(), d.dial)
	m.start()
	sessEdge.expectAccept(t)
	defer m.stop()

	tn := New(Options{Kind: proto.KindDevice, FlushRecordings: func(ctx context.Context) { <-ctx.Done() }})
	tn.sessionMux.Store(m)
	agentSide, edgeSide := net.Pipe()
	defer agentSide.Close()
	defer edgeSide.Close()
	tn.raw, tn.conn = agentSide, proto.NewConn(agentSide)
	// The receive loop's interrupt left a past deadline.
	_ = agentSide.SetReadDeadline(time.Now())
	edge := &fakeEdge{conn: proto.NewConn(edgeSide)}

	got := make(chan *proto.ShutdownPayload, 1)
	go func() { got <- tn.drainReadingControl(t.Context(), true) }()
	edge.send(t, proto.MsgShutdown, proto.ShutdownPayload{Code: "SE040", Retryable: boolPtr(true), RetryAfter: 60})
	edge.send(t, proto.MsgShutdown, proto.ShutdownPayload{Reason: "tunnel has been deleted", Code: "SE018", Retryable: boolPtr(false)})
	select {
	case sd := <-got:
		if sd == nil || sd.Code != "SE018" {
			t.Fatalf("drainReadingControl = %+v, want the SE018 Shutdown", sd)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a terminal Shutdown did not end the drain")
	}
}

// A draining device answers the edge's heartbeats: the edge drops a control
// connection that stays silent past its read deadline, which would cut the
// recording flush short.
func TestDrainReadingControlAnswersHeartbeats(t *testing.T) {
	sessEdge := newFakeSessionEdge(t)
	d := &pipeSessionDial{edge: sessEdge}
	m := newSessionMux(context.Background(), "test", newStreamEchoHandler(), d.dial)
	m.start()
	sessEdge.expectAccept(t)
	defer m.stop()

	tn := New(Options{Kind: proto.KindDevice, FlushRecordings: func(ctx context.Context) { <-ctx.Done() }})
	tn.sessionMux.Store(m)
	agentSide, edgeSide := net.Pipe()
	defer agentSide.Close()
	defer edgeSide.Close()
	tn.raw, tn.conn = agentSide, proto.NewConn(agentSide)
	_ = agentSide.SetReadDeadline(time.Now())
	edge := &fakeEdge{conn: proto.NewConn(edgeSide)}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); tn.drainReadingControl(ctx, true) }()
	edge.send(t, proto.MsgHeartbeat, proto.HeartbeatPayload{Timestamp: 42})
	var ack proto.HeartbeatAckPayload
	if err := json.Unmarshal(edge.expect(t, proto.MsgHeartbeatAck), &ack); err != nil || ack.Timestamp != 42 {
		t.Fatalf("heartbeat ack %+v, %v; want timestamp 42", ack, err)
	}
	cancel()
	<-done
}

package tunnel

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/proto"
	"github.com/localport/agent/internal/transport"
)

// The wait of a hinted refusal stays below min(5 min, max(hint, backoff)), the
// backoff doubling from 30 s.
func TestRefusalWaitBounds(t *testing.T) {
	for n := 1; n <= 8; n++ {
		for _, hint := range []time.Duration{0, time.Minute, 10 * time.Minute} {
			upper := min(maxRefusalWait, max(hint, refusalBackoffBase<<min(n-1, 4)))
			for range 200 {
				if d := refusalWait(hint, n); d < 0 || d >= upper {
					t.Fatalf("refusalWait(%v, %d) = %v, want in [0, %v)", hint, n, d, upper)
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

func startRefusalRun(t *testing.T, opts Options) *refusalRun {
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

// A device refused with a retry_after hint keeps retrying, waiting within the
// hint's window and publishing the code, and runs once a registration is
// accepted; it never reaches its credential or ends.
func TestHintedRefusalKeepsADeviceRetrying(t *testing.T) {
	cred := &fakeCredential{presentation: &identity.Presentation{Serial: "aa"}}
	r := startRefusalRun(t, Options{Kind: proto.KindDevice, Credential: cred, DisableMux: true})

	r.register(t, proto.RegisterAckPayload{Error: "plan is paused", ErrorCode: "BL012", Retryable: boolPtr(false), RetryAfter: 60})
	if d := r.nextWait(t); d >= time.Minute {
		t.Fatalf("first wait %v, want under the 60 s hint", d)
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

// drain ends the handler's sessions before the recordings flush runs, with
// the mux still published, and stop does not shut the handler down again.
func TestSessionMuxDrainOrder(t *testing.T) {
	edge := newFakeSessionEdge(t)
	d := &pipeSessionDial{edge: edge}
	h := newStreamEchoHandler()
	m := newSessionMux(context.Background(), "test", h, d.dial)
	m.start()
	edge.expectAccept(t)

	var shutdownsAtFlush int32 = -1
	m.drain(func(ctx context.Context) {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("the flush runs without a bound")
		}
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

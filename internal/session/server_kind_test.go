package session

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// testKind echoes data records, taps them as output into the session's
// recorder, and counts the contract calls run makes. selfEnd delivers the
// reason the kind ends the session with; onEnd runs inside End.
type testKind struct {
	ch      *Channel
	login   string
	user    *userRecord
	rec     *sessionRecorder
	selfEnd chan string
	onEnd   func(k *testKind)

	handled atomic.Int32
	ends    atomic.Int32
	waits   atomic.Int32
}

func (k *testKind) Handle(m Message) error {
	k.handled.Add(1)
	if m.Type != TypeData {
		return fail(CodeProtocolError, "the test kind accepts only data records")
	}
	k.rec.output(m.Body, nil)
	return k.ch.WriteMessage(TypeData, m.Body)
}

func (k *testKind) Ended() <-chan string { return k.selfEnd }

func (k *testKind) End() {
	k.ends.Add(1)
	if k.onEnd != nil {
		k.onEnd(k)
	}
}

func (k *testKind) Wait() { k.waits.Add(1) }

// kindServer is a testServer whose terminal tickets run testKind. made
// receives each kind once its constructor returns; gate, when set, holds
// the constructor until it is closed; edit adjusts each kind before use.
type kindServer struct {
	*testServer
	made chan *testKind
	gate chan struct{}
	edit func(k *testKind)
}

func newTestKindServer(t *testing.T, edit func(*ServerConfig)) *kindServer {
	t.Helper()
	ks := &kindServer{testServer: newTestServer(t, edit), made: make(chan *testKind, 64)}
	start := func(ch *Channel, _ []byte, login string, user *userRecord, rec *sessionRecorder) (kindSession, error) {
		rec.start(time.Now(), 80, 24)
		if ks.gate != nil {
			<-ks.gate
		}
		k := &testKind{ch: ch, login: login, user: user, rec: rec, selfEnd: make(chan string, 1)}
		if ks.edit != nil {
			ks.edit(k)
		}
		ks.made <- k
		return k, nil
	}
	ks.kinds = func(kind string) prepareKind {
		if kind != "terminal" {
			return nil
		}
		return func(string, *userRecord, bool, func(string, ...any)) (newKind, error) { return start, nil }
	}
	return ks
}

// kind returns the next kind the server made.
func (ks *kindServer) kind(t *testing.T) *testKind {
	t.Helper()
	select {
	case k := <-ks.made:
		return k
	case <-time.After(5 * time.Second):
		t.Fatal("no kind started")
		return nil
	}
}

// waitArmed waits for the next NewTimer call.
func (c *fakeClock) waitArmed(t *testing.T) {
	t.Helper()
	select {
	case <-c.armed:
	case <-time.After(5 * time.Second):
		t.Fatal("no idle timer armed")
	}
}

// Fire sends on the newest timer's channel.
func (c *fakeClock) Fire() {
	c.mu.Lock()
	ch := c.timers[len(c.timers)-1]
	now := c.now
	c.mu.Unlock()
	ch <- now
}

// failingSync writes through and fails every fsync.
type failingSync struct{ jtiWriter }

func (failingSync) Sync() error { return errors.New("fsync failed") }

type testClient struct {
	conn net.Conn
	ch   *Channel
	done <-chan struct{}
}

// open runs a session with raw through the accept frame and sends start.
func (ts *testServer) open(t *testing.T, raw []byte) *testClient {
	t.Helper()
	return ts.openStart(t, raw, []byte(`{}`))
}

// openStart is open with the start record body start.
func (ts *testServer) openStart(t *testing.T, raw, start []byte) *testClient {
	t.Helper()
	c, done := ts.serve(t)
	writeTicket(t, c, raw)
	m, body, err := firstFrame(t, c)
	if err != nil || m["type"] != "accept" {
		t.Fatalf("first frame %v, %v; want accept", m, err)
	}
	var msg AcceptMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		t.Fatal(err)
	}
	keys, err := Open(raw, ts.f.spkiDER, &msg, ts.f.client)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := keys.ClientChannel(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteMessage(TypeStart, start); err != nil {
		t.Fatal(err)
	}
	return &testClient{conn: c, ch: ch, done: done}
}

func (ts *testServer) ticketN(t *testing.T, n int) []byte {
	return ts.ticket(t, func(p *Ticket) { p.JTI = fmt.Sprintf("0190a000-0000-7000-8000-%012d", n) })
}

// expectClose reads the agent's next record and requires close {reason}.
func (c *testClient) expectClose(t *testing.T, reason string) {
	t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	m, err := c.ch.ReadMessage()
	if err != nil || m.Type != TypeClose || m.Reason != reason {
		t.Fatalf("got %v %q, %v; want close %q", m.Type, m.Reason, err, reason)
	}
}

// expectData reads the agent's next record and requires data s.
func (c *testClient) expectData(t *testing.T, s string) {
	t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	m, err := c.ch.ReadMessage()
	if err != nil || m.Type != TypeData || string(m.Body) != s {
		t.Fatalf("got %v %q, %v; want data %q", m.Type, m.Body, err, s)
	}
}

// expectEnd requires the agent's stream to end without a further record.
func (c *testClient) expectEnd(t *testing.T) {
	t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if m, err := c.ch.ReadMessage(); codeOf(err) != CodeTruncated {
		t.Fatalf("got %v %q, %v; want the stream to end", m.Type, m.Body, err)
	}
}

func (c *testClient) echo(t *testing.T, s string) {
	t.Helper()
	if err := c.ch.WriteMessage(TypeData, []byte(s)); err != nil {
		t.Fatal(err)
	}
	c.expectData(t, s)
}

func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

// The kind gets the ticket's login; End and Wait run once on an agent end.
func TestServeRunsTheKindContract(t *testing.T) {
	ts := newTestKindServer(t, nil)
	c := ts.open(t, ts.ticket(t, nil))
	k := ts.kind(t)
	if k.login != "pi" {
		t.Fatalf("kind login %q, want the ticket's pi", k.login)
	}
	c.echo(t, "hello")
	ts.clock.waitArmed(t)
	ts.clock.Advance(idleTimeout)
	ts.clock.Fire()
	c.expectClose(t, CloseIdle)
	c.conn.Close()
	waitDone(t, c.done)
	if e, w := k.ends.Load(), k.waits.Load(); e != 1 || w != 1 {
		t.Fatalf("End ran %d times and Wait %d, want 1 each", e, w)
	}
}

// A kind that ends the session itself gets its close reason sent and is
// joined, without End.
func TestServeClosesWithTheKindsOwnEnd(t *testing.T) {
	ts := newTestKindServer(t, nil)
	c := ts.open(t, ts.ticket(t, nil))
	k := ts.kind(t)
	c.echo(t, "running")
	if err := k.ch.WriteMessage(TypeKindBase+1, []byte(`{"code":0}`)); err != nil {
		t.Fatal(err)
	}
	k.selfEnd <- CloseExited
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if m, err := c.ch.ReadMessage(); err != nil || m.Type != TypeKindBase+1 {
		t.Fatalf("got %v, %v; want the kind's exit record", m.Type, err)
	}
	c.expectClose(t, CloseExited)
	c.expectEnd(t)
	c.conn.Close()
	waitDone(t, c.done)
	if e, w := k.ends.Load(), k.waits.Load(); e != 0 || w != 1 {
		t.Fatalf("End ran %d times and Wait %d, want 0 and 1", e, w)
	}
}

// A record arriving after the server recorded an idle end never reaches
// Handle.
func TestServeHandlesNoRecordAfterTheEnd(t *testing.T) {
	ts := newTestKindServer(t, nil)
	c := ts.open(t, ts.ticket(t, nil))
	k := ts.kind(t)
	// The round trip puts the reader past its start, so the idle count runs
	// from the fake clock's current time.
	c.echo(t, "before the end")
	ts.clock.waitArmed(t)
	ts.clock.Advance(idleTimeout)
	ts.clock.Fire()
	c.expectClose(t, CloseIdle)
	if err := c.ch.WriteMessage(TypeData, []byte("late input")); err != nil {
		t.Fatal(err)
	}
	if err := c.ch.WriteClose("done"); err != nil {
		t.Fatal(err)
	}
	c.conn.Close()
	waitDone(t, c.done)
	if n := k.handled.Load(); n != 1 {
		t.Fatalf("Handle got %d records, want only the one before the idle end", n)
	}
}

// Kind output written between the end decision and close goes out before
// close; output after close is refused ErrChannelClosed and never sent.
func TestServeSendsNoRecordAfterClose(t *testing.T) {
	ts := newTestKindServer(t, nil)
	ts.edit = func(k *testKind) {
		k.onEnd = func(k *testKind) {
			if err := k.ch.WriteMessage(TypeData, []byte("before close")); err != nil {
				t.Errorf("output before close: %v", err)
			}
		}
	}
	c := ts.open(t, ts.ticket(t, nil))
	k := ts.kind(t)
	c.echo(t, "running")
	ts.clock.waitArmed(t)
	ts.clock.Advance(idleTimeout)
	ts.clock.Fire()
	c.expectData(t, "before close")
	c.expectClose(t, CloseIdle)
	if err := k.ch.WriteMessage(TypeData, []byte("after close")); !errors.Is(err, ErrChannelClosed) {
		t.Fatalf("output after close = %v, want ErrChannelClosed", err)
	}
	c.expectEnd(t)
	c.conn.Close()
	waitDone(t, c.done)
}

// A Shutdown while the kind starts sends close {shutdown}; the kind that
// starts after the end is ended and joined by the reader, once.
func TestShutdownWhileTheKindStarts(t *testing.T) {
	ts := newTestKindServer(t, nil)
	ts.gate = make(chan struct{})
	c := ts.open(t, ts.ticket(t, nil))
	shut := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shut <- ts.Shutdown(ctx)
	}()
	c.expectClose(t, CloseShutdown)
	close(ts.gate)
	k := ts.kind(t)
	c.conn.Close()
	waitDone(t, c.done)
	if err := <-shut; err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	if e, w, h := k.ends.Load(), k.waits.Load(), k.handled.Load(); e != 1 || w != 1 || h != 0 {
		t.Fatalf("End %d, Wait %d, Handle %d; want 1, 1, 0", e, w, h)
	}
}

// LiveSessions counts the streams holding a slot.
func TestServerCountsLiveSessions(t *testing.T) {
	ts := newTestKindServer(t, nil)
	c := ts.open(t, ts.ticket(t, nil))
	c.echo(t, "live")
	if n := ts.LiveSessions(); n != 1 {
		t.Fatalf("LiveSessions = %d, want 1", n)
	}
	c.conn.Close()
	waitDone(t, c.done)
	if n := ts.LiveSessions(); n != 0 {
		t.Fatalf("LiveSessions = %d after the end, want 0", n)
	}
}

func TestServeRefusesAReplayedTicket(t *testing.T) {
	ts := newTestKindServer(t, nil)
	raw := ts.ticket(t, nil)
	c := ts.open(t, raw)
	c.conn.Close()
	waitDone(t, c.done)
	if got := ts.refusal(t, raw); got != CodeTicketReplayed {
		t.Fatalf("second use refused %q, want ticket_replayed", got)
	}
}

// A ninth concurrent session is refused agent_busy, unspent; a freed slot
// serves again.
func TestServeCapsSessionsAtEight(t *testing.T) {
	ts := newTestKindServer(t, nil)
	var live []*testClient
	for i := range maxSessions {
		live = append(live, ts.open(t, ts.ticketN(t, i)))
	}
	ninth := ts.ticketN(t, 100)
	if got := ts.refusal(t, ninth); got != CodeAgentBusy {
		t.Fatalf("ninth session refused %q, want agent_busy", got)
	}
	live[0].conn.Close()
	waitDone(t, live[0].done)
	ts.open(t, ninth).echo(t, "served")
}

// A failed fsync refuses agent_busy and leaves the entry out, so the same
// ticket is served once the log works.
func TestServeRefusesWhenTheSpendIsNotDurable(t *testing.T) {
	ts, events := lookupServer(t)
	ts.jti.mu.Lock()
	real := ts.jti.out
	ts.jti.out = failingSync{real}
	ts.jti.mu.Unlock()
	raw := ts.ticket(t, nil)
	if got := ts.refusal(t, raw); got != CodeAgentBusy {
		t.Fatalf("refused %q, want agent_busy", got)
	}
	if ts.spent(ts.f.payload().JTI) {
		t.Fatal("an unsynced spend is held as spent")
	}
	if !events.has("the replay log cannot record the ticket") {
		t.Fatalf("the spend failure was not logged: %q", events.lines)
	}
	ts.jti.mu.Lock()
	ts.jti.out = real
	ts.jti.mu.Unlock()
	ts.open(t, raw).echo(t, "served")
}

// switchSigner fails every signature while fail is set.
type switchSigner struct {
	crypto.Signer
	fail *atomic.Bool
}

func (s switchSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.fail.Load() {
		return nil, errors.New("signing key unavailable")
	}
	return s.Signer.Sign(r, digest, opts)
}

// A handshake failure refuses before the spend: a local signing failure is
// agent_busy and a low-order client key ticket_invalid, and neither spends
// the ticket, so it is served once the signer works.
func TestServeAcceptFailureLeavesTheTicketUnspent(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	ts := newTestKindServer(t, func(c *ServerConfig) {
		certificate := c.Certificate
		c.Certificate = func() (*tls.Certificate, bool) {
			cert, ok := certificate()
			failing := *cert
			failing.PrivateKey = switchSigner{cert.PrivateKey.(crypto.Signer), &fail}
			return &failing, ok
		}
	})
	raw := ts.ticket(t, nil)
	if got := ts.refusal(t, raw); got != CodeAgentBusy {
		t.Fatalf("signing failure refused %q, want agent_busy", got)
	}
	if ts.spent(ts.f.payload().JTI) {
		t.Fatal("a signing failure spent the ticket")
	}
	lowOrder := ts.ticket(t, func(p *Ticket) {
		p.JTI = "0190a000-0000-7000-8000-000000000077"
		p.ClientX25519 = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	})
	if got := ts.refusal(t, lowOrder); got != CodeTicketInvalid {
		t.Fatalf("low-order client key refused %q, want ticket_invalid", got)
	}
	if ts.spent("0190a000-0000-7000-8000-000000000077") {
		t.Fatal("a low-order client key spent the ticket")
	}
	fail.Store(false)
	ts.open(t, raw).echo(t, "served")
}

// A stream past its ticket read when Shutdown starts, here waiting on the
// key refresh, is refused a delivered agent_busy, not reset, and unspent.
func TestShutdownRefusesAStreamInItsChecks(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var known atomic.Bool
	ts := newTestKindServer(t, nil)
	ts.cfg.Lookup = func(kid string) (ed25519.PublicKey, bool) {
		if !known.Load() {
			return nil, false
		}
		return ts.f.lookup(kid)
	}
	ts.cfg.RefreshKeys = func(context.Context) error {
		close(entered)
		<-release
		known.Store(true)
		return nil
	}
	s, done := ts.serveReset(t, ts.ticket(t, nil))
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no key refresh")
	}
	// A done context returns Shutdown once it stopped every handler.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ts.Shutdown(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Shutdown = %v, want context.Canceled while the stream is served", err)
	}
	close(release)
	if code := firstAnswer(t, s, done); code != CodeAgentBusy {
		t.Fatalf("refused %q, want agent_busy", code)
	}
	if ts.spent(ts.f.payload().JTI) {
		t.Fatal("a stream refused by Shutdown spent the ticket")
	}
}

// 30 minutes without client data or activity closes idle; client data
// restarts the count.
func TestServeClosesAnIdleSession(t *testing.T) {
	ts := newTestKindServer(t, nil)
	c := ts.open(t, ts.ticket(t, nil))
	ts.clock.waitArmed(t)
	ts.clock.Advance(20 * time.Minute)
	c.echo(t, "typing")
	ts.clock.Advance(10 * time.Minute)
	ts.clock.Fire()
	ts.clock.waitArmed(t) // 10 minutes idle: re-armed, not closed
	ts.clock.Advance(20 * time.Minute)
	ts.clock.Fire()
	c.expectClose(t, CloseIdle)
	c.conn.Close()
	waitDone(t, c.done)
}

// A first record that is not start closes protocol_error.
func TestServeClosesWhenTheFirstRecordIsNotStart(t *testing.T) {
	ts := newTestKindServer(t, nil)
	raw := ts.ticket(t, nil)
	conn, done := ts.serve(t)
	writeTicket(t, conn, raw)
	_, body, err := firstFrame(t, conn)
	if err != nil {
		t.Fatal(err)
	}
	var msg AcceptMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		t.Fatal(err)
	}
	keys, err := Open(raw, ts.f.spkiDER, &msg, ts.f.client)
	if err != nil {
		t.Fatal(err)
	}
	ch, _ := keys.ClientChannel(conn)
	if err := ch.WriteMessage(TypeData, []byte("early")); err != nil {
		t.Fatal(err)
	}
	c := &testClient{conn: conn, ch: ch, done: done}
	c.expectClose(t, CodeProtocolError)
	waitDone(t, done)
}

// Shutdown sends close {shutdown} to the sessions it finds, refuses streams
// that arrive while it runs, and returns once they end; the next control
// session's streams are then served by the same server.
func TestShutdownEndsTheStoppingMuxSessionsOnly(t *testing.T) {
	ts := newTestKindServer(t, nil)
	first := ts.open(t, ts.ticketN(t, 1))
	first.echo(t, "first")

	shut := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		shut <- ts.Shutdown(ctx)
	}()
	first.expectClose(t, CloseShutdown)
	// Shutdown waits for first, which has not answered yet.
	if got := ts.refusal(t, ts.ticketN(t, 2)); got != CodeAgentBusy {
		t.Fatalf("a stream during Shutdown refused %q, want agent_busy", got)
	}
	first.conn.Close()
	if err := <-shut; err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	waitDone(t, first.done)

	next := ts.open(t, ts.ticketN(t, 3))
	next.echo(t, "next control session")
}

// After Shutdown and the stream closes that follow it, no session goroutine
// is left.
func TestNothingOutlivesShutdown(t *testing.T) {
	before := runtime.NumGoroutine()
	ts := newTestKindServer(t, nil)
	var live []*testClient
	for i := range 4 {
		c := ts.open(t, ts.ticketN(t, i))
		c.echo(t, "x")
		live = append(live, c)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		for _, c := range live {
			c.expectClose(t, CloseShutdown)
			c.conn.Close()
		}
	}()
	if err := ts.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	ts.wg.Wait()
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		buf := make([]byte, 1<<16)
		t.Fatalf("%d goroutines after Shutdown, %d before:\n%s", n, before, buf[:runtime.Stack(buf, true)])
	}
}

// A client close ends the session with no agent close; activity records do
// not reach the kind; the ticket stays spent.
func TestServeRunsUntilTheClientCloses(t *testing.T) {
	ts := newTestKindServer(t, nil)
	c := ts.open(t, ts.ticket(t, nil))
	k := ts.kind(t)
	c.echo(t, "hello")
	if err := c.ch.WriteMessage(TypeActivity, nil); err != nil {
		t.Fatal(err)
	}
	c.echo(t, "again")
	if err := c.ch.WriteClose("done"); err != nil {
		t.Fatal(err)
	}
	waitDone(t, c.done)
	if m, err := c.ch.ReadMessage(); codeOf(err) != CodeTruncated {
		t.Fatalf("after the client close got %v, %v; want the stream to end without an agent close", m.Type, err)
	}
	if n := k.handled.Load(); n != 2 {
		t.Fatalf("Handle got %d records, want the 2 data records", n)
	}
	if !ts.spent(ts.f.payload().JTI) {
		t.Fatal("the accepted ticket is not spent")
	}
}

// A ticket with rec is served only for terminal and only when the held team
// recording key hashes to its pub_sha256; a mismatch refreshes the keys once.
// Every refusal leaves the ticket unspent.
func TestServeChecksTheTicketRec(t *testing.T) {
	want := sha256.Sum256([]byte("team recording key"))
	other := sha256.Sum256([]byte("another team key"))
	errDeclined := errors.New("declined by the refresh floor")
	for _, c := range []struct {
		name      string
		kind      string
		held      *[sha256.Size]byte // nil holds no key
		refreshed *[sha256.Size]byte // the held key after a refresh; nil leaves it
		refuseErr error
		refreshes int32
		code      string
	}{
		{name: "matching key", kind: "terminal", held: &want, code: "accept"},
		{name: "rec on ssh", kind: "ssh", held: &want, code: CodeKindUnavailable},
		{name: "refresh brings the key", kind: "terminal", held: &other, refreshed: &want, refreshes: 1, code: "accept"},
		{name: "no key until the refresh", kind: "terminal", refreshed: &want, refreshes: 1, code: "accept"},
		{name: "still another key", kind: "terminal", held: &other, refreshed: &other, refreshes: 1, code: CodeRecordingKeyMismatch},
		{name: "refresh declined", kind: "terminal", held: &other, refuseErr: errDeclined, refreshes: 1, code: CodeRecordingKeyMismatch},
	} {
		t.Run(c.name, func(t *testing.T) {
			var held atomic.Pointer[[sha256.Size]byte]
			held.Store(c.held)
			var refreshes atomic.Int32
			ts := newTestKindServer(t, func(cfg *ServerConfig) {
				cfg.Capabilities = []string{"terminal"}
				cfg.RecordingKey = func() ([]byte, [sha256.Size]byte, bool) {
					sum := held.Load()
					if sum == nil {
						return nil, [sha256.Size]byte{}, false
					}
					return []byte("key"), *sum, true
				}
				cfg.RefreshKeys = func(ctx context.Context) error {
					refreshes.Add(1)
					if _, ok := ctx.Deadline(); !ok {
						t.Error("the refresh has no deadline")
					}
					if c.refuseErr != nil {
						return c.refuseErr
					}
					if c.refreshed != nil {
						held.Store(c.refreshed)
					}
					return nil
				}
			})
			terminal := ts.kinds("terminal")
			ts.kinds = func(string) prepareKind { return terminal }
			raw := ts.ticket(t, func(p *Ticket) {
				p.Kind = c.kind
				p.JTI = recJTI
				p.Rec = testRec(recJTI)
			})
			if got := ts.refusal(t, raw); got != c.code {
				t.Fatalf("answered %q, want %q", got, c.code)
			}
			if n := refreshes.Load(); n != c.refreshes {
				t.Fatalf("%d refreshes, want %d", n, c.refreshes)
			}
			if spent := ts.spent(recJTI); spent != (c.code == "accept") {
				t.Fatalf("spent = %t after %q", spent, c.code)
			}
		})
	}
}

// A validly signed ticket refused on the device clock is logged with the
// difference; a ticket refused before its signature verifies is not logged.
func TestServeLogsAClockRefusalWithTheDifference(t *testing.T) {
	ts, events := lookupServer(t)
	future := ts.ticket(t, func(p *Ticket) { p.IAT += 3600; p.EXP += 3600 })
	if got := ts.refusal(t, future); got != CodeTicketExpired {
		t.Fatalf("refused %q, want %s", got, CodeTicketExpired)
	}
	if !events.has("ahead of this device's clock") {
		t.Fatalf("the clock refusal was not logged: %q", events.lines)
	}
	if got := ts.refusal(t, []byte("not.a-ticket")); got != CodeTicketInvalid {
		t.Fatalf("refused %q, want %s", got, CodeTicketInvalid)
	}
	if events.has("ticket refused: ticket_invalid") {
		t.Fatalf("an unsigned refusal was logged: %q", events.lines)
	}
}

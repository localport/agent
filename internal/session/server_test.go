package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a manual clock. Fire sends on the newest timer's channel.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []chan time.Time
	armed  chan struct{} // receives one value per NewTimer
}

func newFakeClock(now time.Time) *fakeClock {
	return &fakeClock{now: now, armed: make(chan struct{}, 64)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTimer(time.Duration) (<-chan time.Time, func() bool) {
	ch := make(chan time.Time, 1)
	c.mu.Lock()
	c.timers = append(c.timers, ch)
	c.mu.Unlock()
	c.armed <- struct{}{}
	return ch, func() bool { return true }
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// deviceCert is a self-signed certificate over the fixture's device key.
func deviceCert(t *testing.T, f *fixture) *tls.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "abc123"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<33, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &f.device.PublicKey, f.device)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: f.device, Leaf: leaf}
}

// testServer is a server for the fixture's device with terminal enabled for
// login pi, a fake clock at testNow and a jti log in a temp dir.
type testServer struct {
	*Server
	f     *fixture
	clock *fakeClock
	jti   *JTILog
	wg    sync.WaitGroup
}

func newTestServer(t *testing.T, edit func(*ServerConfig)) *testServer {
	t.Helper()
	f := newFixture(t, "server")
	clk := newFakeClock(testNow)
	jti, err := OpenJTILog(t.TempDir(), clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { jti.Close() })
	cert := deviceCert(t, f)
	cfg := ServerConfig{
		Prefix:       "abc123",
		Certificate:  func() (*tls.Certificate, bool) { return cert, true },
		Lookup:       f.lookup,
		Capabilities: []string{"terminal"},
		Logins:       []string{"pi"},
		JTI:          jti,
		clock:        clk,
	}
	if edit != nil {
		edit(&cfg)
	}
	ts := &testServer{Server: NewServer(cfg), f: f, clock: clk, jti: jti}
	// The agent runs as root and every login has an account.
	ts.users = func(_ context.Context, login string) (*userRecord, error) { return testUser(login, 1000), nil }
	ts.euid = func() int { return 0 }
	t.Cleanup(ts.wg.Wait)
	return ts
}

// serve hands one stream to Serve, closing it after Serve returns as the
// session mux does, and returns the client side and Serve's done channel.
func (ts *testServer) serve(t *testing.T) (net.Conn, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	agent, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	done := make(chan struct{})
	ts.wg.Go(func() {
		defer close(done)
		ts.Serve(agent)
		agent.Close()
	})
	return client, done
}

func (ts *testServer) ticket(t *testing.T, edit func(*Ticket)) []byte {
	t.Helper()
	p := ts.f.payload()
	if edit != nil {
		edit(&p)
	}
	return sign(t, ts.f.ticketKey, p)
}

func writeTicket(t *testing.T, c net.Conn, raw []byte) {
	t.Helper()
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(raw)))
	if _, err := c.Write(append(frame, raw...)); err != nil {
		t.Fatal(err)
	}
}

// firstFrame reads the agent's first frame; io.EOF when the stream ended
// without one.
func firstFrame(t *testing.T, c net.Conn) (map[string]string, []byte, error) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return nil, nil, err
	}
	body := make([]byte, binary.BigEndian.Uint32(head[:]))
	if _, err := io.ReadFull(c, body); err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	return m, body, nil
}

var errStreamReset = errors.New("stream reset")

// resetStream is a session stream with the delivery semantics of the tunnel's
// sessionStream: Close resets it and drops the bytes the peer has not read,
// CloseWrite ends it after every written byte, and an expired deadline resets
// it (at once for a deadline not in the future). The peer methods are the
// edge's side.
type resetStream struct {
	in     *io.PipeReader // edge to agent
	peerIn *io.PipeWriter

	mu     sync.Mutex
	cond   *sync.Cond
	out    []byte // agent to edge, not yet read by the peer
	eof    bool   // CloseWrite
	reset  bool
	wrote  bool
	timers [2]*time.Timer
	// acted is closed at the agent's first Read, CloseWrite or Close after
	// its first Write, so the peer reads only once the agent moved on.
	acted     chan struct{}
	actedOnce sync.Once
}

func newResetStream() *resetStream {
	r, w := io.Pipe()
	s := &resetStream{in: r, peerIn: w, acted: make(chan struct{})}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *resetStream) act() {
	s.mu.Lock()
	wrote := s.wrote
	s.mu.Unlock()
	if wrote {
		s.actedOnce.Do(func() { close(s.acted) })
	}
}

func (s *resetStream) Read(p []byte) (int, error) {
	s.act()
	return s.in.Read(p)
}

func (s *resetStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reset || s.eof {
		return 0, errStreamReset
	}
	s.out = append(s.out, p...)
	s.wrote = true
	s.cond.Broadcast()
	return len(p), nil
}

func (s *resetStream) CloseWrite() error {
	s.act()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eof = true
	s.cond.Broadcast()
	return nil
}

func (s *resetStream) Close() error {
	s.act()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.reset {
		s.reset = true
		s.out = nil
		for _, tm := range s.timers {
			if tm != nil {
				tm.Stop()
			}
		}
		_ = s.in.CloseWithError(errStreamReset)
		s.cond.Broadcast()
	}
	return nil
}

func (s *resetStream) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (s *resetStream) RemoteAddr() net.Addr { return &net.TCPAddr{} }

func (s *resetStream) SetDeadline(t time.Time) error {
	_ = s.SetReadDeadline(t)
	return s.SetWriteDeadline(t)
}

func (s *resetStream) SetReadDeadline(t time.Time) error  { return s.arm(0, t) }
func (s *resetStream) SetWriteDeadline(t time.Time) error { return s.arm(1, t) }

func (s *resetStream) arm(i int, t time.Time) error {
	if !t.IsZero() && !t.After(time.Now()) {
		return s.Close()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.timers[i] != nil {
		s.timers[i].Stop()
		s.timers[i] = nil
	}
	if !t.IsZero() && !s.reset {
		s.timers[i] = time.AfterFunc(time.Until(t), func() { _ = s.Close() })
	}
	return nil
}

// peerRead reads what the agent wrote; errStreamReset once the stream was
// reset, io.EOF after CloseWrite and the last byte.
func (s *resetStream) peerRead(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.out) == 0 && !s.eof && !s.reset {
		s.cond.Wait()
	}
	if s.reset {
		return 0, errStreamReset
	}
	if len(s.out) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.out)
	s.out = s.out[n:]
	return n, nil
}

// peerFrame reads one length-prefixed frame the agent wrote.
func (s *resetStream) peerFrame() ([]byte, error) {
	var head [4]byte
	if _, err := io.ReadFull(readerFunc(s.peerRead), head[:]); err != nil {
		return nil, err
	}
	body := make([]byte, binary.BigEndian.Uint32(head[:]))
	if _, err := io.ReadFull(readerFunc(s.peerRead), body); err != nil {
		return nil, err
	}
	return body, nil
}

func (s *resetStream) peerFirstFrame() (map[string]string, error) {
	body, err := s.peerFrame()
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// resetPeer is the edge's side of a resetStream as a net.Conn: Close resets
// the stream, and an expired read deadline resets it, which ends a blocked
// Read.
type resetPeer struct {
	s     *resetStream
	mu    sync.Mutex
	timer *time.Timer
}

func (p *resetPeer) Read(b []byte) (int, error)  { return p.s.peerRead(b) }
func (p *resetPeer) Write(b []byte) (int, error) { return p.s.peerIn.Write(b) }
func (p *resetPeer) Close() error                { return p.s.Close() }
func (p *resetPeer) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (p *resetPeer) RemoteAddr() net.Addr        { return &net.TCPAddr{} }
func (p *resetPeer) SetDeadline(t time.Time) error {
	return p.SetReadDeadline(t)
}
func (p *resetPeer) SetWriteDeadline(time.Time) error { return nil }

func (p *resetPeer) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
	if !t.IsZero() {
		p.timer = time.AfterFunc(time.Until(t), func() { _ = p.s.Close() })
	}
	return nil
}

// openResetStart runs a session with raw over a resetStream through the
// accept frame and sends start; the client's conn is the edge's side.
func (ts *testServer) openResetStart(t *testing.T, raw, start []byte) *testClient {
	t.Helper()
	s, done := ts.serveReset(t, raw)
	body, err := s.peerFrame()
	if err != nil {
		t.Fatalf("first frame: %v", err)
	}
	var msg AcceptMessage
	if err := json.Unmarshal(body, &msg); err != nil || msg.Type != "accept" {
		t.Fatalf("first frame %s, %v; want accept", body, err)
	}
	keys, err := Open(raw, ts.f.spkiDER, &msg, ts.f.client)
	if err != nil {
		t.Fatal(err)
	}
	peer := &resetPeer{s: s}
	ch, err := keys.ClientChannel(peer)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteMessage(TypeStart, start); err != nil {
		t.Fatal(err)
	}
	return &testClient{conn: peer, ch: ch, done: done}
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// serveReset hands one resetStream to Serve and closes it after Serve
// returns, as the session mux does.
func (ts *testServer) serveReset(t *testing.T, raw []byte) (*resetStream, <-chan struct{}) {
	t.Helper()
	s := newResetStream()
	t.Cleanup(func() { _ = s.Close() })
	done := make(chan struct{})
	ts.wg.Go(func() {
		defer close(done)
		ts.Serve(s)
		_ = s.Close()
	})
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(raw)))
	go func() { _, _ = s.peerIn.Write(append(frame, raw...)) }()
	return s, done
}

// refusal opens a stream with raw and returns the refused code, or "accept".
// The stream is reset by Close, so a refused frame counts only when the agent
// delivered it before closing.
func (ts *testServer) refusal(t *testing.T, raw []byte) string {
	t.Helper()
	s, done := ts.serveReset(t, raw)
	return firstAnswer(t, s, done)
}

// firstAnswer reads the first frame of a stream from serveReset as the edge
// does, ends the stream and waits for Serve.
func firstAnswer(t *testing.T, s *resetStream, done <-chan struct{}) string {
	t.Helper()
	select {
	case <-s.acted:
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("no first frame within 10 s")
	}
	m, err := s.peerFirstFrame()
	if err != nil {
		t.Fatalf("first frame not delivered: %v", err)
	}
	if m["type"] == "accept" {
		_ = s.Close()
	} else {
		// The edge ends its side once it read the refusal.
		_ = s.peerIn.Close()
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return")
	}
	if m["type"] == "accept" {
		return "accept"
	}
	return m["code"]
}

func (ts *testServer) spent(jti string) bool {
	ts.jti.mu.Lock()
	defer ts.jti.mu.Unlock()
	_, ok := ts.jti.entries[jti]
	return ok
}

// Every check before the spend refuses with its code and leaves the ticket
// unspent.
func TestServeRefusesBeforeTheSpend(t *testing.T) {
	other := ed25519.NewKeyFromSeed(fixed("another ticket key"))
	for _, c := range []struct {
		name   string
		config func(*ServerConfig)
		ticket func(*testServer) []byte
		code   string
	}{
		{"forged", nil, func(ts *testServer) []byte { return sign(t, other, ts.f.payload()) }, CodeTicketInvalid},
		{"expired", func(c *ServerConfig) {}, func(ts *testServer) []byte {
			ts.clock.Advance(91 * time.Second)
			return ts.ticket(t, nil)
		}, CodeTicketExpired},
		{"wrong device", nil, func(ts *testServer) []byte { return ts.ticket(t, func(p *Ticket) { p.Device = "zzz999" }) }, CodeTicketWrongDevice},
		{"kind disabled", func(c *ServerConfig) { c.Capabilities = []string{"files"} }, nil, CodeKindDisabled},
		{"desktop without target", func(c *ServerConfig) { c.Capabilities = []string{"desktop"} }, func(ts *testServer) []byte {
			return ts.ticket(t, func(p *Ticket) { p.Kind, p.Login = "vnc", "" })
		}, CodeKindDisabled},
		{"login not allowed", func(c *ServerConfig) { c.Logins = []string{"root"} }, nil, CodeLoginNotAllowed},
		{"no registered certificate", func(c *ServerConfig) {
			c.Certificate = func() (*tls.Certificate, bool) { return nil, false }
		}, nil, CodeAgentBusy},
	} {
		t.Run(c.name, func(t *testing.T) {
			ts := newTestServer(t, c.config)
			raw := ts.ticket(t, nil)
			if c.ticket != nil {
				raw = c.ticket(ts)
			}
			if got := ts.refusal(t, raw); got != c.code {
				t.Fatalf("refused %q, want %q", got, c.code)
			}
			if ts.spent(ts.f.payload().JTI) {
				t.Fatal("a refusal before the spend spent the ticket")
			}
		})
	}
}

// An unknown kid triggers one key refresh and one retry.
func TestServeRefreshesOnceForAnUnknownKid(t *testing.T) {
	for _, c := range []struct {
		name      string
		refreshed bool // the refresh brings the kid
		unknown   bool // still ticket_unknown_key
	}{{"refresh brings the key", true, false}, {"still unknown", false, true}} {
		t.Run(c.name, func(t *testing.T) {
			var refreshes atomic.Int32
			var known atomic.Bool
			ts := newTestServer(t, nil)
			ts.cfg.Lookup = func(kid string) (ed25519.PublicKey, bool) {
				if !known.Load() {
					return nil, false
				}
				return ts.f.lookup(kid)
			}
			ts.cfg.RefreshKeys = func(ctx context.Context) error {
				refreshes.Add(1)
				if _, ok := ctx.Deadline(); !ok {
					t.Error("the refresh has no deadline")
				}
				known.Store(c.refreshed)
				return nil
			}
			got := ts.refusal(t, ts.ticket(t, nil))
			if n := refreshes.Load(); n != 1 {
				t.Fatalf("%d refreshes, want 1", n)
			}
			if (got == CodeTicketUnknownKey) != c.unknown {
				t.Fatalf("refused %q; want ticket_unknown_key: %v", got, c.unknown)
			}
		})
	}
}

// A ticket longer than 8 KiB ends the stream without a frame or a read of
// its body.
func TestServeRefusesAnOversizeTicket(t *testing.T) {
	ts := newTestServer(t, nil)
	c, done := ts.serve(t)
	writeTicket(t, c, make([]byte, maxTicketBytes+1))
	if m, _, err := firstFrame(t, c); err == nil {
		t.Fatalf("got frame %v, want the stream to end", m)
	}
	<-done
}

// A stream that never sends its ticket ends at the read timeout.
func TestServeTicketReadTimesOut(t *testing.T) {
	prev := ticketReadTimeout
	ticketReadTimeout = 50 * time.Millisecond
	defer func() { ticketReadTimeout = prev }()
	ts := newTestServer(t, nil)
	_, done := ts.serve(t)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve still waits for the ticket after the read timeout")
	}
}

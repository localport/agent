package tunnel

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/localport/agent/internal/proto"
	"github.com/localport/agent/internal/transport"
)

// fakeSessionEdge plays the edge's session mux server: HTTP/2 with prior
// knowledge, the accept stream and session streams.
type fakeSessionEdge struct {
	notices  chan []byte
	accepted chan acceptRequest
	sessions chan *edgeStream
	// recording, when set before the mux starts, serves /v1/recording/*.
	recording http.HandlerFunc
	// stall, when set before the mux starts, holds each session stream before
	// its response headers until it closes; stalled receives the request
	// context of each held stream.
	stall   chan struct{}
	stalled chan context.Context

	mu      sync.Mutex
	servers []*http.Server
}

type acceptRequest struct {
	contentLength int64
	bodyEOF       bool
}

// edgeStream is one session stream as the edge sees it. Its handler holds the
// stream until done is closed or the request ends.
type edgeStream struct {
	id    string
	body  io.Reader
	w     http.ResponseWriter
	rc    *http.ResponseController
	done  chan struct{}
	ended <-chan struct{}
}

func newFakeSessionEdge(t *testing.T) *fakeSessionEdge {
	e := &fakeSessionEdge{
		notices:  make(chan []byte),
		accepted: make(chan acceptRequest, 8),
		sessions: make(chan *edgeStream, 8),
	}
	t.Cleanup(e.close)
	return e
}

func (e *fakeSessionEdge) close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, s := range e.servers {
		_ = s.Close()
	}
}

// serveConn serves conn as the edge until it closes.
func (e *fakeSessionEdge) serveConn(conn net.Conn) {
	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	server := &http.Server{
		Handler:   e,
		Protocols: &protocols,
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams: 21,
			MaxReadFrameSize:     16 << 10,
		},
	}
	e.mu.Lock()
	e.servers = append(e.servers, server)
	e.mu.Unlock()
	_ = server.Serve(&muxListener{conn: conn})
}

func (e *fakeSessionEdge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	switch {
	case r.Method == http.MethodPost && r.URL.Path == sessionAcceptPath:
		n, err := r.Body.Read(make([]byte, 1))
		e.accepted <- acceptRequest{contentLength: r.ContentLength, bodyEOF: n == 0 && errors.Is(err, io.EOF)}
		w.WriteHeader(http.StatusOK)
		if rc.Flush() != nil {
			return
		}
		for {
			select {
			case <-r.Context().Done():
				return
			case b := <-e.notices:
				if _, err := w.Write(b); err != nil || rc.Flush() != nil {
					return
				}
			}
		}
	case r.Method == http.MethodPost && r.URL.Path == sessionStreamPath:
		if e.stall != nil {
			e.stalled <- r.Context()
			select {
			case <-e.stall:
			case <-r.Context().Done():
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		if rc.Flush() != nil {
			return
		}
		s := &edgeStream{id: r.Header.Get(sessionIDHeader), body: r.Body, w: w, rc: rc, done: make(chan struct{}), ended: r.Context().Done()}
		e.sessions <- s
		select {
		case <-s.done:
		case <-r.Context().Done():
		}
	case e.recording != nil && strings.HasPrefix(r.URL.Path, "/v1/recording/"):
		e.recording(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// noticeSerial is the certificate serial every test notice carries.
const noticeSerial uint64 = 0x0123456789abcdef

func notice(id [sessionIDLen]byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, sessionNoticeLen)
	b = append(b, id[:]...)
	return binary.BigEndian.AppendUint64(b, noticeSerial)
}

func (e *fakeSessionEdge) sendNotice(t *testing.T, b []byte) {
	t.Helper()
	select {
	case e.notices <- b:
	case <-time.After(3 * time.Second):
		t.Fatal("no accept stream took the notice")
	}
}

func (e *fakeSessionEdge) expectAccept(t *testing.T) acceptRequest {
	t.Helper()
	select {
	case a := <-e.accepted:
		return a
	case <-time.After(3 * time.Second):
		t.Fatal("the agent did not open the accept stream")
		return acceptRequest{}
	}
}

func (e *fakeSessionEdge) expectSession(t *testing.T) *edgeStream {
	t.Helper()
	select {
	case s := <-e.sessions:
		return s
	case <-time.After(3 * time.Second):
		t.Fatal("the agent did not open a session stream")
		return nil
	}
}

func (s *edgeStream) write(t *testing.T, b []byte) {
	t.Helper()
	if _, err := s.w.Write(b); err != nil {
		t.Fatalf("edge write: %v", err)
	}
	if err := s.rc.Flush(); err != nil {
		t.Fatalf("edge flush: %v", err)
	}
}

// readWithin reads exactly n bytes from r or fails after 3 s.
func readWithin(t *testing.T, r io.Reader, n int) ([]byte, error) {
	t.Helper()
	type result struct {
		b   []byte
		err error
	}
	got := make(chan result, 1)
	go func() {
		b := make([]byte, n)
		_, err := io.ReadFull(r, b)
		got <- result{b, err}
	}()
	select {
	case res := <-got:
		return res.b, res.err
	case <-time.After(3 * time.Second):
		t.Fatal("read timed out")
		return nil, nil
	}
}

// streamEchoHandler echoes each stream. Its Shutdown runs shutdown, by
// default a farewell: write "bye", half-close, and wait for every Serve.
type streamEchoHandler struct {
	mu       sync.Mutex
	live     map[net.Conn]chan struct{}
	served   atomic.Int32
	serving  chan struct{}
	shutdown func(ctx context.Context) error

	shutdownCalls atomic.Int32
	recordingUps  atomic.Int32
	farewellErr   chan error
	// lastID and lastSerial are the notice values of the latest Serve.
	lastID     atomic.Pointer[[16]byte]
	lastSerial atomic.Uint64
}

func newStreamEchoHandler() *streamEchoHandler {
	h := &streamEchoHandler{
		live:        make(map[net.Conn]chan struct{}),
		serving:     make(chan struct{}, 8),
		farewellErr: make(chan error, 8),
	}
	h.shutdown = h.farewell
	return h
}

func (h *streamEchoHandler) Serve(stream net.Conn, id [16]byte, serial uint64) {
	h.lastID.Store(&id)
	h.lastSerial.Store(serial)
	done := make(chan struct{})
	h.mu.Lock()
	h.live[stream] = done
	h.mu.Unlock()
	h.served.Add(1)
	h.serving <- struct{}{}
	defer func() {
		h.mu.Lock()
		delete(h.live, stream)
		h.mu.Unlock()
		close(done)
	}()
	_, _ = io.Copy(stream, stream)
}

func (h *streamEchoHandler) Shutdown(ctx context.Context) error {
	h.shutdownCalls.Add(1)
	return h.shutdown(ctx)
}

func (h *streamEchoHandler) RecordingClientUp() { h.recordingUps.Add(1) }

func (h *streamEchoHandler) LiveSessions() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.live)
}

func (h *streamEchoHandler) snapshot() map[net.Conn]chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	return maps.Clone(h.live)
}

func (h *streamEchoHandler) farewell(ctx context.Context) error {
	for stream, done := range h.snapshot() {
		_, err := stream.Write([]byte("bye"))
		if err == nil {
			err = stream.(interface{ CloseWrite() error }).CloseWrite()
		}
		h.farewellErr <- err
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (h *streamEchoHandler) waitServing(t *testing.T) {
	t.Helper()
	select {
	case <-h.serving:
	case <-time.After(3 * time.Second):
		t.Fatal("the stream did not reach the handler")
	}
}

// pipeSessionDial dials a net.Pipe whose far end the edge serves, after
// failing the first failures dials.
type pipeSessionDial struct {
	edge     *fakeSessionEdge
	failures int
	dials    atomic.Int32
}

func (d *pipeSessionDial) dial(context.Context) (net.Conn, error) {
	n := d.dials.Add(1)
	if int(n) <= d.failures {
		return nil, errors.New("mux bind refused: test")
	}
	agentSide, edgeSide := net.Pipe()
	go d.edge.serveConn(edgeSide)
	return agentSide, nil
}

// startTestSessionMux runs a session mux with immediate backoff.
func startTestSessionMux(t *testing.T, h SessionHandler, dial func(context.Context) (net.Conn, error)) *sessionMux {
	t.Helper()
	m := newSessionMux(context.Background(), "test", h, dial)
	m.sleep = func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }
	m.start()
	t.Cleanup(m.stop)
	return m
}

// goroutinesSettle fails unless the goroutine count drops to at most before.
func goroutinesSettle(t *testing.T, before int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			t.Fatalf("goroutines: %d, want at most %d\n%s", runtime.NumGoroutine(), before, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func sessionDeviceTunnel(opts Options) *Tunnel {
	opts.Kind = proto.KindDevice
	opts.Edge = "connect.eu.localport.dev:443"
	return New(opts)
}

func TestSessionMuxIsBoundOnlyForAnEnabledDevice(t *testing.T) {
	h := newStreamEchoHandler()
	for _, tc := range []struct {
		name string
		tn   *Tunnel
		want bool
	}{
		{"enabled", sessionDeviceTunnel(Options{SessionHandler: h, Capabilities: []string{"files"}}), true},
		{"desktop", sessionDeviceTunnel(Options{SessionHandler: h, Capabilities: []string{"desktop"}}), true},
		{"no handler", sessionDeviceTunnel(Options{Capabilities: []string{"terminal"}}), false},
		{"no session capability", sessionDeviceTunnel(Options{SessionHandler: h, Capabilities: []string{"ports"}}), false},
		{"no capability", sessionDeviceTunnel(Options{SessionHandler: h}), false},
		{"no mux", sessionDeviceTunnel(Options{SessionHandler: h, Capabilities: []string{"terminal"}, DisableMux: true}), false},
		{"host tunnel", New(Options{SessionHandler: h, Capabilities: []string{"terminal"}, Local: "127.0.0.1:1"}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.tn.sessionMuxEnabled(); got != tc.want {
				t.Fatalf("sessionMuxEnabled = %v, want %v", got, tc.want)
			}
		})
	}
}

// bindingDialer answers the MuxBind exchange, then serves the edge's session
// mux on the conn.
type bindingDialer struct {
	edge     *fakeSessionEdge
	purposes chan string
}

func (d *bindingDialer) Kind() transport.Kind { return transport.KindRaw }

func (d *bindingDialer) Dial(context.Context, string, string) (net.Conn, error) {
	agentSide, edgeSide := net.Pipe()
	go func() {
		pc := proto.NewConn(edgeSide)
		mt, body, err := pc.Recv()
		var bind proto.MuxBindPayload
		if err != nil || mt != proto.MsgMuxBind || json.Unmarshal(body, &bind) != nil {
			_ = edgeSide.Close()
			return
		}
		d.purposes <- bind.Purpose
		if err := pc.Send(proto.MsgMuxBindAck, &proto.MuxBindAckPayload{Success: true}); err != nil {
			_ = edgeSide.Close()
			return
		}
		d.edge.serveConn(edgeSide)
	}()
	return agentSide, nil
}

// A device binds its session mux with purpose "session". Cancelling the
// control session's context alone leaves the conn up: Shutdown still reaches
// the edge over it when the stop function runs.
func TestSessionMuxBindsWithSessionPurposeAndOutlivesTheRunContext(t *testing.T) {
	edge := newFakeSessionEdge(t)
	d := &bindingDialer{edge: edge, purposes: make(chan string, 4)}
	h := newStreamEchoHandler()
	tn := sessionDeviceTunnel(Options{SessionHandler: h, Capabilities: []string{"terminal"}})
	tn.mu.Lock()
	tn.sessionID, tn.dialer, tn.edgeAddr = "s1", d, "connect.eu.localport.dev:443"
	tn.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	stop := tn.startSessionMux(ctx)
	t.Cleanup(stop)

	select {
	case p := <-d.purposes:
		if p != proto.MuxBindPurposeSession {
			t.Fatalf("MuxBind purpose = %q, want %q", p, proto.MuxBindPurposeSession)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no MuxBind")
	}
	edge.expectAccept(t)
	edge.sendNotice(t, notice([sessionIDLen]byte{1}))
	s := edge.expectSession(t)
	h.waitServing(t)
	if id := h.lastID.Load(); id == nil || *id != [sessionIDLen]byte{1} || h.lastSerial.Load() != noticeSerial {
		t.Fatalf("Serve got id %v serial %x, want the notice's", id, h.lastSerial.Load())
	}

	cancel()
	s.write(t, []byte("ping"))
	if b, err := readWithin(t, s.body, 4); err != nil || string(b) != "ping" {
		t.Fatalf("after the run context ended the stream echoed %q, %v; the conn closed early", b, err)
	}

	farewell := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(s.body)
		farewell <- b
		close(s.done)
	}()
	stop()
	if err := <-h.farewellErr; err != nil {
		t.Fatalf("Shutdown could not write on its stream: %v", err)
	}
	if b := <-farewell; string(b) != "bye" {
		t.Fatalf("edge read %q, want the farewell", b)
	}
}

func TestSessionMuxOpensOneStreamPerNotice(t *testing.T) {
	edge := newFakeSessionEdge(t)
	d := &pipeSessionDial{edge: edge}
	h := newStreamEchoHandler()
	h.shutdown = func(context.Context) error { return nil }
	startTestSessionMux(t, h, d.dial)

	if a := edge.expectAccept(t); a.contentLength != 0 || !a.bodyEOF {
		t.Fatalf("accept request = %+v, want no body", a)
	}

	for _, id := range [][sessionIDLen]byte{{0xaa, 1}, {0xbb, 2}} {
		edge.sendNotice(t, notice(id))
		s := edge.expectSession(t)
		if s.id != hex.EncodeToString(id[:]) {
			t.Fatalf("%s = %q, want %x", sessionIDHeader, s.id, id)
		}
		h.waitServing(t)
		s.write(t, []byte("data"))
		if b, err := readWithin(t, s.body, 4); err != nil || string(b) != "data" {
			t.Fatalf("echo = %q, %v", b, err)
		}
	}
	select {
	case s := <-edge.sessions:
		t.Fatalf("an extra session stream %q was opened", s.id)
	default:
	}
	if n := h.served.Load(); n != 2 {
		t.Fatalf("Serve ran %d times, want 2", n)
	}
	if n := d.dials.Load(); n != 1 {
		t.Fatalf("dials = %d, want 1 while the accept stream is up", n)
	}
}

func TestSessionMuxRedialsAfterABadNotice(t *testing.T) {
	edge := newFakeSessionEdge(t)
	d := &pipeSessionDial{edge: edge}
	startTestSessionMux(t, newStreamEchoHandler(), d.dial)

	edge.expectAccept(t)
	edge.sendNotice(t, binary.BigEndian.AppendUint32(nil, 15))
	edge.expectAccept(t)
	if n := d.dials.Load(); n != 2 {
		t.Fatalf("dials = %d, want a redial after the bad notice", n)
	}
}

func TestSessionMuxRedialsAfterTheEdgeDropsTheConn(t *testing.T) {
	edge := newFakeSessionEdge(t)
	d := &pipeSessionDial{edge: edge}
	startTestSessionMux(t, newStreamEchoHandler(), d.dial)

	edge.expectAccept(t)
	edge.close()
	edge.expectAccept(t)
	if n := d.dials.Load(); n != 2 {
		t.Fatalf("dials = %d, want 2", n)
	}
}

// Failed binds back off with growing attempts; an answered mux that stayed up
// sessionMuxStableAfter resets them.
func TestSessionMuxBacksOffAfterFailedBinds(t *testing.T) {
	edge := newFakeSessionEdge(t)
	d := &pipeSessionDial{edge: edge, failures: 9}
	var mu sync.Mutex
	var attempts []int
	m := newSessionMux(context.Background(), "test", newStreamEchoHandler(), d.dial)
	clock := fakeMuxClock(m)
	m.backoff = func(attempt int) time.Duration {
		mu.Lock()
		attempts = append(attempts, attempt)
		mu.Unlock()
		return 0
	}
	m.sleep = func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }
	m.start()
	t.Cleanup(m.stop)

	edge.expectAccept(t)
	mu.Lock()
	got := slices.Clone(attempts)
	mu.Unlock()
	if want := []int{0, 1, 2, 3, 4, 5, 6, 7, 8}; !slices.Equal(got, want) {
		t.Fatalf("backoff attempts = %v, want %v", got, want)
	}

	// A session stream shows the agent read the accept stream's 200.
	edge.sendNotice(t, notice([sessionIDLen]byte{3}))
	edge.expectSession(t)
	clock.Add(int64(sessionMuxStableAfter))
	edge.close()
	edge.expectAccept(t)
	mu.Lock()
	last := attempts[len(attempts)-1]
	mu.Unlock()
	if last != 0 {
		t.Fatalf("backoff after a dropped bound mux started at attempt %d, want 0", last)
	}
}

// A bind whose accept stream is refused keeps the backoff growing; only a mux
// answered 200 that stayed up sessionMuxStableAfter resets it.
func TestSessionMuxBackoffResetsOnlyAfterTheAcceptStreamAnswered(t *testing.T) {
	edge := newFakeSessionEdge(t)
	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	refusing := &http.Server{Handler: http.NotFoundHandler(), Protocols: &protocols}
	t.Cleanup(func() { _ = refusing.Close() })

	const refusals = 5
	var dials atomic.Int32
	dial := func(context.Context) (net.Conn, error) {
		agentSide, edgeSide := net.Pipe()
		if dials.Add(1) <= refusals {
			go func() { _ = refusing.Serve(&muxListener{conn: edgeSide}) }()
		} else {
			go edge.serveConn(edgeSide)
		}
		return agentSide, nil
	}
	var mu sync.Mutex
	var attempts []int
	m := newSessionMux(context.Background(), "test", newStreamEchoHandler(), dial)
	clock := fakeMuxClock(m)
	m.backoff = func(attempt int) time.Duration {
		mu.Lock()
		attempts = append(attempts, attempt)
		mu.Unlock()
		return 0
	}
	m.sleep = func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }
	m.start()
	t.Cleanup(m.stop)

	edge.expectAccept(t)
	mu.Lock()
	got := slices.Clone(attempts)
	mu.Unlock()
	if want := []int{0, 1, 2, 3, 4}; !slices.Equal(got, want) {
		t.Fatalf("backoff attempts after %d refused accept streams = %v, want %v", refusals, got, want)
	}

	// A session stream shows the agent read the accept stream's 200.
	edge.sendNotice(t, notice([sessionIDLen]byte{4}))
	edge.expectSession(t)
	clock.Add(int64(sessionMuxStableAfter))
	edge.close()
	edge.expectAccept(t)
	mu.Lock()
	last := attempts[len(attempts)-1]
	mu.Unlock()
	if last != 0 {
		t.Fatalf("backoff after a dropped accepted mux started at attempt %d, want 0", last)
	}
}

// within returns the next value from ch, failing the test after 3 seconds.
func within[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting")
		var zero T
		return zero
	}
}

// stallingSessionEdge is a fake edge that holds every session stream before
// its response headers.
func stallingSessionEdge(t *testing.T) *fakeSessionEdge {
	edge := newFakeSessionEdge(t)
	edge.stall = make(chan struct{})
	edge.stalled = make(chan context.Context, 2*maxSessionOpens)
	t.Cleanup(func() { close(edge.stall) })
	return edge
}

// At most maxSessionOpens opens wait on the edge at once; the next notice is
// read but its open waits for a slot.
func TestSessionMuxBoundsTheOpensInFlight(t *testing.T) {
	edge := stallingSessionEdge(t)
	m := newSessionMux(context.Background(), "test", newStreamEchoHandler(), (&pipeSessionDial{edge: edge}).dial)
	m.openTimeout = time.Hour
	m.start()
	t.Cleanup(m.stop)
	edge.expectAccept(t)

	for i := range maxSessionOpens + 1 {
		edge.sendNotice(t, notice([sessionIDLen]byte{byte(i + 1)}))
	}
	for range maxSessionOpens {
		within(t, edge.stalled)
	}
	select {
	case <-edge.stalled:
		t.Fatalf("open %d started while %d were in flight", maxSessionOpens+1, maxSessionOpens)
	case <-time.After(200 * time.Millisecond):
	}
}

// An open whose response headers do not arrive within openTimeout is reset,
// which frees its slot.
func TestSessionMuxResetsAStalledOpen(t *testing.T) {
	edge := stallingSessionEdge(t)
	m := newSessionMux(context.Background(), "test", newStreamEchoHandler(), (&pipeSessionDial{edge: edge}).dial)
	m.openTimeout = 50 * time.Millisecond
	m.start()
	t.Cleanup(m.stop)
	edge.expectAccept(t)

	edge.sendNotice(t, notice([sessionIDLen]byte{1}))
	held := within(t, edge.stalled)
	select {
	case <-held.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the stalled open was not reset at its deadline")
	}

	// Reset opens free their slots: a full set of stalled opens is followed by
	// the next notice's open once they time out.
	for i := range maxSessionOpens + 1 {
		edge.sendNotice(t, notice([sessionIDLen]byte{byte(i + 2)}))
	}
	for range maxSessionOpens + 1 {
		within(t, edge.stalled)
	}
}

// fakeMuxClock makes m read its time from the returned nanosecond counter.
func fakeMuxClock(m *sessionMux) *atomic.Int64 {
	var clock atomic.Int64
	m.now = func() time.Time { return time.Unix(0, clock.Load()) }
	return &clock
}

// A mux whose accept stream answered but that dropped before
// sessionMuxStableAfter keeps the backoff growing.
func TestSessionMuxBackoffKeepsGrowingWhenTheMuxDropsEarly(t *testing.T) {
	edge := newFakeSessionEdge(t)
	d := &pipeSessionDial{edge: edge}
	var mu sync.Mutex
	var attempts []int
	m := newSessionMux(context.Background(), "test", newStreamEchoHandler(), d.dial)
	clock := fakeMuxClock(m)
	m.backoff = func(attempt int) time.Duration {
		mu.Lock()
		attempts = append(attempts, attempt)
		mu.Unlock()
		return 0
	}
	m.sleep = func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }
	m.start()
	t.Cleanup(m.stop)

	for i := range 3 {
		edge.expectAccept(t)
		edge.sendNotice(t, notice([sessionIDLen]byte{byte(10 + i)}))
		edge.expectSession(t)
		clock.Add(int64(sessionMuxStableAfter - time.Second))
		edge.close()
	}
	edge.expectAccept(t)
	mu.Lock()
	got := slices.Clone(attempts)
	mu.Unlock()
	if want := []int{0, 1, 2}; !slices.Equal(got, want) {
		t.Fatalf("backoff attempts after muxes that dropped early = %v, want %v", got, want)
	}
}

// stallingBindDialer reads the MuxBind and never answers it.
type stallingBindDialer struct{ binds chan struct{} }

func (d *stallingBindDialer) Kind() transport.Kind { return transport.KindRaw }

func (d *stallingBindDialer) Dial(context.Context, string, string) (net.Conn, error) {
	agentSide, edgeSide := net.Pipe()
	go func() {
		defer edgeSide.Close()
		if mt, _, err := proto.NewConn(edgeSide).Recv(); err == nil && mt == proto.MsgMuxBind {
			d.binds <- struct{}{}
		}
		_, _ = io.Copy(io.Discard, edgeSide)
	}()
	return agentSide, nil
}

// An edge that stalls before MuxBindAck holds stop no longer than the
// Shutdown bound: stop closes the conn of the bind in flight.
func TestSessionMuxStopEndsAStalledBind(t *testing.T) {
	before := runtime.NumGoroutine()
	d := &stallingBindDialer{binds: make(chan struct{}, 1)}
	h := newStreamEchoHandler()
	h.shutdown = func(context.Context) error { return nil }
	tn := sessionDeviceTunnel(Options{SessionHandler: h, Capabilities: []string{"terminal"}})
	tn.mu.Lock()
	tn.sessionID, tn.dialer, tn.edgeAddr = "s1", d, "connect.eu.localport.dev:443"
	tn.mu.Unlock()

	stop := tn.startSessionMux(context.Background())
	select {
	case <-d.binds:
	case <-time.After(3 * time.Second):
		t.Fatal("no MuxBind")
	}

	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(sessionShutdownTimeout + 500*time.Millisecond):
		t.Fatal("stop waited on a bind the edge never answered")
	}
	goroutinesSettle(t, before)
}

// One handler serves every control session: a session mux started after an
// earlier mux on the same handler stopped still hands its streams to Serve.
func TestSessionMuxHandlerServesAgainAfterShutdown(t *testing.T) {
	edge := newFakeSessionEdge(t)
	d := &pipeSessionDial{edge: edge}
	h := newStreamEchoHandler()

	first := newSessionMux(context.Background(), "test", h, d.dial)
	first.start()
	edge.expectAccept(t)
	first.stop()
	if n := h.shutdownCalls.Load(); n != 1 {
		t.Fatalf("Shutdown ran %d times, want 1", n)
	}

	startTestSessionMux(t, h, d.dial)
	edge.expectAccept(t)
	edge.sendNotice(t, notice([sessionIDLen]byte{0xcc}))
	s := edge.expectSession(t)
	h.waitServing(t)
	s.write(t, []byte("next"))
	if b, err := readWithin(t, s.body, 4); err != nil || string(b) != "next" {
		t.Fatalf("echo after Shutdown = %q, %v", b, err)
	}
}

// closeLog records, in order, the handler's Shutdown and the first agent-side
// close of each control and session mux conn.
type closeLog struct {
	mu     sync.Mutex
	events []string
}

func (l *closeLog) add(e string) {
	l.mu.Lock()
	l.events = append(l.events, e)
	l.mu.Unlock()
}

func (l *closeLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.events)
}

// recordedConn logs its first Close under the role the edge gave it. A port
// mux conn is not logged.
type recordedConn struct {
	net.Conn
	log  *closeLog
	role atomic.Pointer[string]
	once sync.Once
}

func (c *recordedConn) Close() error {
	c.once.Do(func() {
		if role := c.role.Load(); role != nil && *role != "port mux" {
			c.log.add(*role + " closed")
		}
	})
	return c.Conn.Close()
}

// runEdgeDialer plays the edge for Run: it acks every Register, refuses the
// port mux bind and serves the session mux on edge.
type runEdgeDialer struct {
	log          *closeLog
	edge         *fakeSessionEdge
	controls     chan net.Conn
	sessionBinds chan struct{}
}

func (d *runEdgeDialer) Kind() transport.Kind { return transport.KindRaw }

func (d *runEdgeDialer) Dial(context.Context, string, string) (net.Conn, error) {
	agentSide, edgeSide := net.Pipe()
	rec := &recordedConn{Conn: agentSide, log: d.log}
	go d.serve(rec, edgeSide)
	return rec, nil
}

func (d *runEdgeDialer) serve(rec *recordedConn, edgeSide net.Conn) {
	setRole := func(r string) { rec.role.Store(&r) }
	pc := proto.NewConn(edgeSide)
	mt, body, err := pc.Recv()
	if err != nil {
		_ = edgeSide.Close()
		return
	}
	switch mt {
	case proto.MsgRegister:
		setRole("control")
		if pc.Send(proto.MsgRegisterAck, &proto.RegisterAckPayload{Success: true, SessionID: "s1"}) != nil {
			_ = edgeSide.Close()
			return
		}
		d.controls <- edgeSide
		_, _ = io.Copy(io.Discard, edgeSide)
	case proto.MsgMuxBind:
		var bind proto.MuxBindPayload
		if json.Unmarshal(body, &bind) != nil || bind.Purpose != proto.MuxBindPurposeSession {
			setRole("port mux")
			_ = pc.Send(proto.MsgMuxBindAck, &proto.MuxBindAckPayload{Success: false, Error: "test"})
			_ = edgeSide.Close()
			return
		}
		setRole("session mux")
		d.sessionBinds <- struct{}{}
		if pc.Send(proto.MsgMuxBindAck, &proto.MuxBindAckPayload{Success: true}) != nil {
			_ = edgeSide.Close()
			return
		}
		d.edge.serveConn(edgeSide)
	default:
		_ = edgeSide.Close()
	}
}

func (d *runEdgeDialer) expectControl(t *testing.T) net.Conn {
	t.Helper()
	select {
	case c := <-d.controls:
		return c
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not register")
		return nil
	}
}

func (d *runEdgeDialer) expectSessionBind(t *testing.T) {
	t.Helper()
	select {
	case <-d.sessionBinds:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not bind a session mux")
	}
}

// When the edge ends a control session, Run shuts the session handler down
// before it closes the session mux conn, and both before the control conn;
// the reconnect binds a fresh session mux.
func TestRunStopsTheSessionMuxBeforeClosingTheControlConn(t *testing.T) {
	before := runtime.NumGoroutine()
	log := &closeLog{}
	edge := newFakeSessionEdge(t)
	d := &runEdgeDialer{log: log, edge: edge, controls: make(chan net.Conn, 2), sessionBinds: make(chan struct{}, 2)}
	h := newStreamEchoHandler()
	h.shutdown = func(context.Context) error {
		log.add("shutdown")
		return nil
	}
	tn := sessionDeviceTunnel(Options{SessionHandler: h, Capabilities: []string{"terminal"}})
	tn.newDialers = func(transport.Options) []transport.Dialer { return []transport.Dialer{d} }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := make(chan error, 1)
	go func() { ran <- tn.Run(ctx) }()

	control := d.expectControl(t)
	d.expectSessionBind(t)
	edge.expectAccept(t)

	tn.retryNow <- struct{}{} // skip the reconnect backoff
	_ = control.Close()

	second := d.expectControl(t)
	defer second.Close()
	d.expectSessionBind(t)
	edge.expectAccept(t)
	if got, want := log.snapshot(), []string{"shutdown", "session mux closed", "control closed"}; !slices.Equal(got, want) {
		t.Fatalf("first control session ended with %v, want %v", got, want)
	}

	cancel()
	select {
	case err := <-ran:
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	goroutinesSettle(t, before)
}

// Run closes the control conn when ctx ends the session; no caller holds it.
func TestRunClosesTheControlConnOnCancel(t *testing.T) {
	before := runtime.NumGoroutine()
	log := &closeLog{}
	edge := newFakeSessionEdge(t)
	d := &runEdgeDialer{log: log, edge: edge, controls: make(chan net.Conn, 1), sessionBinds: make(chan struct{}, 1)}
	tn := sessionDeviceTunnel(Options{SessionHandler: newStreamEchoHandler(), Capabilities: []string{"terminal"}})
	tn.newDialers = func(transport.Options) []transport.Dialer { return []transport.Dialer{d} }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := make(chan error, 1)
	go func() { ran <- tn.Run(ctx) }()

	defer d.expectControl(t).Close()
	d.expectSessionBind(t)
	edge.expectAccept(t)

	cancel()
	select {
	case err := <-ran:
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if got := log.snapshot(); !slices.Contains(got, "control closed") {
		t.Fatalf("after cancel the close log is %v, want the control conn closed", got)
	}
	goroutinesSettle(t, before)
}

func TestSessionMuxBackoffGrowsAndCaps(t *testing.T) {
	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60, 60}
	for attempt, w := range want {
		ceil := sessionMuxBackoffCeiling(attempt)
		if ceil != w*time.Second {
			t.Fatalf("ceiling(%d) = %v, want %v", attempt, ceil, w*time.Second)
		}
		for range 100 {
			if d := sessionMuxBackoff(attempt); d <= 0 || d > ceil {
				t.Fatalf("backoff(%d) = %v, want in (0, %v]", attempt, d, ceil)
			}
		}
	}
	if c := sessionMuxBackoffCeiling(1 << 20); c != sessionMuxBackoffCeil {
		t.Fatalf("ceiling of a huge attempt = %v", c)
	}
}

// The agent's SETTINGS and connection window are the session mux bounds.
func TestSessionMuxClientSettings(t *testing.T) {
	edgeSides := make(chan net.Conn, 1)
	dial := func(context.Context) (net.Conn, error) {
		agentSide, edgeSide := net.Pipe()
		edgeSides <- edgeSide
		return agentSide, nil
	}
	m := startTestSessionMux(t, newStreamEchoHandler(), dial)
	edgeSide := <-edgeSides
	defer edgeSide.Close()

	_ = edgeSide.SetReadDeadline(time.Now().Add(5 * time.Second))
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(edgeSide, preface); err != nil || string(preface) != http2.ClientPreface {
		t.Fatalf("preface = %q, %v", preface, err)
	}
	fr := http2.NewFramer(nil, edgeSide)
	var settings, window bool
	for !settings || !window {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			settings = true
			if v, ok := f.Value(http2.SettingMaxFrameSize); !ok || v != 16<<10 {
				t.Errorf("MAX_FRAME_SIZE = %d, want 16 KiB", v)
			}
			// Go advertises MaxResponseHeaderBytes plus 320 bytes of per-field
			// overhead.
			if v, ok := f.Value(http2.SettingMaxHeaderListSize); !ok || v != 4<<10+320 {
				t.Errorf("MAX_HEADER_LIST_SIZE = %d, want 4 KiB + 320", v)
			}
			if v, ok := f.Value(http2.SettingInitialWindowSize); !ok || v != 128<<10 {
				t.Errorf("INITIAL_WINDOW_SIZE = %d, want 128 KiB", v)
			}
		case *http2.WindowUpdateFrame:
			if f.StreamID == 0 {
				window = true
				if f.Increment != 21*128<<10 {
					t.Errorf("connection WINDOW_UPDATE = %d, want 21 x 128 KiB", f.Increment)
				}
			}
		}
	}
	_ = edgeSide.Close()
	m.stop()
}

// Shutdown runs and returns before the conn closes, so what it writes on its
// stream reaches the edge; nothing is left running after stop.
func TestSessionMuxStopShutsDownBeforeClosingTheConn(t *testing.T) {
	before := runtime.NumGoroutine()
	edge := newFakeSessionEdge(t)
	d := &pipeSessionDial{edge: edge}
	h := newStreamEchoHandler()
	m := newSessionMux(context.Background(), "test", h, d.dial)
	m.start()

	edge.expectAccept(t)
	edge.sendNotice(t, notice([sessionIDLen]byte{7}))
	s := edge.expectSession(t)
	h.waitServing(t)

	farewell := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(s.body)
		farewell <- b
		close(s.done)
	}()

	m.stop()
	m.stop()
	if err := <-h.farewellErr; err != nil {
		t.Fatalf("Shutdown could not write on its stream: %v", err)
	}
	if b := <-farewell; string(b) != "bye" {
		t.Fatalf("edge read %q, want the farewell before the conn closed", b)
	}
	if n := h.shutdownCalls.Load(); n != 1 {
		t.Fatalf("Shutdown ran %d times", n)
	}
	edge.close()
	goroutinesSettle(t, before)
}

// A Shutdown that outlasts its bound holds stop only until the bound; the
// conn then closes, which ends its sessions and so the Shutdown.
func TestSessionMuxStopIsBoundedBySlowShutdown(t *testing.T) {
	before := runtime.NumGoroutine()
	edge := newFakeSessionEdge(t)
	d := &pipeSessionDial{edge: edge}
	h := newStreamEchoHandler()
	h.shutdown = func(context.Context) error {
		for _, done := range h.snapshot() {
			<-done
		}
		return nil
	}
	m := newSessionMux(context.Background(), "test", h, d.dial)
	m.shutdownTimeout = 100 * time.Millisecond
	m.start()

	edge.expectAccept(t)
	edge.sendNotice(t, notice([sessionIDLen]byte{8}))
	edge.expectSession(t)
	h.waitServing(t)

	stopped := make(chan struct{})
	start := time.Now()
	go func() { m.stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("stop waited on a Shutdown past its bound")
	}
	if took := time.Since(start); took < m.shutdownTimeout {
		t.Fatalf("stop returned after %v, before the Shutdown bound", took)
	}
	edge.close()
	goroutinesSettle(t, before)
}

// A notice that arrives while Shutdown runs gets its stream opened and closed,
// never handed to Serve.
func TestSessionMuxHandsNoStreamOverOnceStopBegan(t *testing.T) {
	edge := newFakeSessionEdge(t)
	d := &pipeSessionDial{edge: edge}
	h := newStreamEchoHandler()
	inShutdown := make(chan struct{})
	release := make(chan struct{})
	h.shutdown = func(context.Context) error {
		close(inShutdown)
		<-release
		return nil
	}
	m := newSessionMux(context.Background(), "test", h, d.dial)
	m.start()
	edge.expectAccept(t)

	stopped := make(chan struct{})
	go func() { m.stop(); close(stopped) }()
	<-inShutdown

	edge.sendNotice(t, notice([sessionIDLen]byte{9}))
	s := edge.expectSession(t)
	select {
	case <-s.ended:
	case <-time.After(3 * time.Second):
		t.Fatal("the stream opened during stop was not closed")
	}
	close(release)
	<-stopped
	if n := h.served.Load(); n != 0 {
		t.Fatalf("Serve ran %d times after stop began", n)
	}
}

func TestRegisterAckHandsRevokedTicketKidsToTheHook(t *testing.T) {
	cred := &fakeCredential{}
	tn, d := deviceTunnel(t, cred)
	calls := make(chan []string, 4)
	tn.opts.HintRevoked = func(kids []string) { calls <- kids }

	if err := connectWithAck(t, tn, d, proto.RegisterAckPayload{Success: false, Error: "unavailable", ErrorCode: "ED001", Retryable: boolPtr(true), RevokedTicketKids: []string{"refused"}}); err == nil {
		t.Fatal("a refused registration returned success")
	}
	if err := connectWithAck(t, tn, d, proto.RegisterAckPayload{Success: true, SessionID: "s"}); err != nil {
		t.Fatal(err)
	}
	if err := connectWithAck(t, tn, d, proto.RegisterAckPayload{Success: true, SessionID: "s", RevokedTicketKids: []string{"k1", "k2"}}); err != nil {
		t.Fatal(err)
	}
	select {
	case kids := <-calls:
		if !slices.Equal(kids, []string{"k1", "k2"}) {
			t.Fatalf("hook got %v, want the successful ack's kids", kids)
		}
	default:
		t.Fatal("the hook was not called before the registration returned")
	}
	select {
	case kids := <-calls:
		t.Fatalf("hook called again with %v", kids)
	default:
	}
}

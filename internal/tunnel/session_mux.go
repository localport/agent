package tunnel

import (
	"context"
	"crypto"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/localport/agent/internal/proto"
)

// SessionHandler serves the session streams of a device's session mux. One
// handler serves every control session of the tunnel: each session mux calls
// Shutdown when its control session ends, and the next control session's mux
// calls Serve again on the same handler.
//
// Serve runs on its own goroutine per stream and must return once the stream
// fails. id is the stream's session id from the edge's notice (the bytes of
// the UUID its access row carries and the recordings of channels opened on
// it name) and serial the serial of
// the SSH user certificate the edge admitted for it. The session mux closes
// stream after Serve returns. Shutdown ends the
// sessions the handler holds when it is called and must return once ctx ends.
// It is not terminal: Serve may be called again after Shutdown returns, for
// the next control session. No stream of the stopping
// mux is handed to Serve once Shutdown has been called, but a Serve started
// just before may still be running when Shutdown begins.
//
// LiveSessions returns the number of sessions the handler serves now; a
// certificate rollover that is not forced waits while it is above zero.
//
// RecordingClientUp is called each time the mux publishes the recording
// client of a new conn; it must not block.
type SessionHandler interface {
	Serve(stream net.Conn, id [16]byte, serial uint64)
	Shutdown(ctx context.Context) error
	LiveSessions() int
	RecordingClientUp()
}

// Request targets and header of the session mux. The edge is the HTTP/2
// server; the agent holds the accept stream open and opens one session stream
// per notice it reads there.
const (
	sessionAcceptPath = "/v1/session-accept"
	sessionStreamPath = "/v1/session"
	// sessionIDHeader carries the hex session id a session stream answers.
	sessionIDHeader = "Localport-Session-Id"
	sessionIDLen    = 16
	// sessionNoticeLen is a notice body: the session id, then the admitted
	// certificate serial as uint64 big-endian.
	sessionNoticeLen = sessionIDLen + 8
	// sessionMuxAuthority is the :authority of every request. The mux conn
	// reaches exactly one edge, which does not route on it.
	sessionMuxAuthority = "session-mux.invalid"
	// sessionMuxUserAgent names the client; registration carries the version.
	sessionMuxUserAgent = "localport-agent"
)

// HTTP/2 client settings of the session mux. They match the edge's server
// settings (16 KiB frames, 128 KiB stream windows, and a connection window
// worth 22 streams: the accept stream, 16 sessions, 2 segment requests, 1
// open, 1 complete or failed open, and 1 clipboard notice batch), so neither
// side buffers more than the other allows.
const (
	sessionMuxMaxFrame     = 16 << 10
	sessionMuxStreamWindow = 128 << 10
	sessionMuxConnWindow   = 22 * sessionMuxStreamWindow
	// sessionMuxMaxHeaderBytes bounds each response's header list (Go adds
	// 320 bytes of field overhead), as the edge bounds request headers.
	sessionMuxMaxHeaderBytes = 4 << 10
	// A ping after this long of read silence; its answer and every conn write
	// are bounded by the timeout. The edge's session mux uses the same values.
	sessionMuxPingInterval = 30 * time.Second
	sessionMuxPingTimeout  = 15 * time.Second

	// sessionShutdownTimeout bounds the handler's Shutdown when the mux stops:
	// a session's 5 s kill window, which overlaps its 4 s close, then the 3 s
	// bound on its recording's final handoff, plus margin for the reap.
	sessionShutdownTimeout = 10 * time.Second

	sessionMuxBackoffBase = time.Second
	sessionMuxBackoffCeil = 60 * time.Second
	// sessionMuxStableAfter is how long a mux stays up before a failure
	// redials from the shortest backoff again.
	sessionMuxStableAfter = 30 * time.Second

	// maxSessionOpens bounds the session stream opens in flight: a notice
	// beyond it waits, so the accept stream is not read and HTTP/2 flow
	// control holds the edge back. sessionOpenTimeout bounds an open's wait
	// for its response headers.
	maxSessionOpens    = 16
	sessionOpenTimeout = 30 * time.Second
)

// sessionMuxEnabled reports whether this session binds a session mux: a
// device with a session handler and a session capability enabled, on a
// tunnel that does not run with --no-mux.
func (t *Tunnel) sessionMuxEnabled() bool {
	if t.opts.SessionHandler == nil || t.opts.DisableMux || !t.IsDevice() {
		return false
	}
	return slices.ContainsFunc(t.opts.Capabilities, isSessionCapability)
}

func isSessionCapability(c string) bool {
	switch c {
	case "terminal", "files", "desktop":
		return true
	}
	return false
}

// startSessionMux starts the session mux of the current control session and
// returns its stop function. It ignores ctx cancellation: only the stop
// function ends the mux, so the handler's Shutdown runs before the conn
// closes.
func (t *Tunnel) startSessionMux(ctx context.Context) func() {
	if !t.sessionMuxEnabled() {
		return func() {}
	}

	// Read under one lock, so the mux binds the session of this registration
	// with the dialer and client certificate that registered it. The dialer
	// presents presented.Certificate on every dial, and its key signs the
	// recording open and complete requests sent over this mux.
	t.mu.RLock()
	addr, session, dialer, presented := t.edgeAddr, t.sessionID, t.dialer, t.presented
	t.mu.RUnlock()

	m := newSessionMux(context.WithoutCancel(ctx), t.opts.Label, t.opts.SessionHandler,
		func(ctx context.Context) (net.Conn, error) {
			return t.dialAndBindMux(ctx, addr, session, dialer, proto.MuxBindPurposeSession)
		})
	if presented != nil && presented.Certificate != nil {
		signer, ok := presented.Certificate.PrivateKey.(crypto.Signer)
		if !ok {
			slog.Default().Warn("session recording unavailable: the device key cannot sign",
				slog.String("tunnel", t.opts.Label))
		}
		m.signer = signer
	}
	if notices := t.opts.ClipboardNotices; notices != nil {
		identifier := t.Identity()
		// The mux is unpublished before it stops, so the flush is handed the
		// conn's client instead of looking it up.
		m.flushClipboard = func(ctx context.Context) { notices.Flush(ctx, identifier, m.clip.Load()) }
	}
	t.sessionMux.Store(m)
	m.start()
	return func() {
		t.sessionMux.CompareAndSwap(m, nil)
		m.stop()
	}
}

// sessionMux keeps a device's session mux up for one control session. It
// redials a failed bind or a dropped conn with capped, fully jittered backoff
// until stop.
type sessionMux struct {
	label   string
	handler SessionHandler
	dial    func(ctx context.Context) (net.Conn, error)
	// signer is the key of the certificate every dial presents. Without one
	// the mux publishes no recording client. Set before start.
	signer crypto.Signer

	// rec is the recording client of the current conn, nil while no conn's
	// accept stream is up.
	rec atomic.Pointer[RecordingClient]
	// clip is the clipboard notice client of the current conn, nil while no
	// conn's accept stream is up.
	clip atomic.Pointer[ClipboardClient]
	// flushClipboard sends the device's queued clipboard notices; stop runs
	// it after the handler's Shutdown and before the conn closes. Nil sends
	// none. Set before start.
	flushClipboard func(ctx context.Context)

	// Seams for tests.
	backoff         func(attempt int) time.Duration
	sleep           func(ctx context.Context, d time.Duration) bool
	now             func() time.Time
	shutdownTimeout time.Duration
	openTimeout     time.Duration

	// ctx is the mux's own context. Only stop cancels it, and its end closes
	// the current conn.
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	stopOnce sync.Once

	// mu guards stopping and every Add to served, so no stream is handed over
	// once stop has begun.
	mu       sync.Mutex
	stopping bool
	// served counts the handler goroutines (Serve and Shutdown); run waits for
	// it before done closes.
	served sync.WaitGroup
}

func newSessionMux(parent context.Context, label string, handler SessionHandler, dial func(context.Context) (net.Conn, error)) *sessionMux {
	ctx, cancel := context.WithCancel(parent)
	return &sessionMux{
		label:           label,
		handler:         handler,
		dial:            dial,
		backoff:         sessionMuxBackoff,
		sleep:           sleepCtx,
		now:             time.Now,
		shutdownTimeout: sessionShutdownTimeout,
		openTimeout:     sessionOpenTimeout,
		ctx:             ctx,
		cancel:          cancel,
		done:            make(chan struct{}),
	}
}

func (m *sessionMux) start() { go m.run() }

// stop calls the handler's Shutdown with its bound and waits for it, then
// closes the conn and waits for every goroutine the mux started. It is
// idempotent and safe to call concurrently.
func (m *sessionMux) stop() {
	m.stopOnce.Do(func() {
		m.mu.Lock()
		m.stopping = true
		m.served.Add(1)
		m.mu.Unlock()
		m.shutdownHandler()
		if m.flushClipboard != nil {
			ctx, cancel := context.WithTimeout(context.Background(), clipboardFinalFlush)
			m.flushClipboard(ctx)
			cancel()
		}
		m.cancel()
	})
	<-m.done
}

// shutdownHandler runs Shutdown and waits for it at most shutdownTimeout. A
// Shutdown still running past the bound is waited for by run once the conn
// has closed.
func (m *sessionMux) shutdownHandler() {
	ctx, cancel := context.WithTimeout(context.Background(), m.shutdownTimeout)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		defer m.served.Done()
		result <- m.handler.Shutdown(ctx)
	}()
	select {
	case err := <-result:
		if err != nil {
			slog.Default().Warn("session handler shutdown failed",
				slog.String("tunnel", m.label), slog.Any("error", err))
		}
	case <-ctx.Done():
		slog.Default().Warn("session handler shutdown did not finish in time",
			slog.String("tunnel", m.label), slog.Duration("timeout", m.shutdownTimeout))
	}
}

func (m *sessionMux) run() {
	defer close(m.done)
	defer m.served.Wait()

	attempt := 0
	for {
		conn, err := m.dial(m.ctx)
		if err == nil {
			start := m.now()
			var accepted bool
			accepted, err = m.serve(conn)
			// Only an answered mux that stayed up sessionMuxStableAfter
			// resets the backoff; one that drops sooner keeps it growing.
			if accepted && m.now().Sub(start) >= sessionMuxStableAfter {
				attempt = 0
			}
		}
		if m.ctx.Err() != nil {
			return
		}
		level := slog.LevelWarn
		if attempt > 0 {
			level = slog.LevelDebug
		}
		slog.Default().Log(context.Background(), level, "session mux unavailable, retrying",
			slog.String("tunnel", m.label), slog.Any("error", err))
		if !m.sleep(m.ctx, m.backoff(attempt)) {
			return
		}
		attempt++
	}
}

// sessionMuxBackoff is full jitter over min(60 s, 1 s << attempt).
func sessionMuxBackoff(attempt int) time.Duration {
	return rand.N(sessionMuxBackoffCeiling(attempt)) + 1
}

func sessionMuxBackoffCeiling(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt > 6 {
		return sessionMuxBackoffCeil
	}
	return min(sessionMuxBackoffBase<<attempt, sessionMuxBackoffCeil)
}

// serve runs one bound conn: it holds the accept stream and opens a session
// stream per notice until the conn or the accept stream ends, or the mux
// stops. It returns after the conn is closed and every stream open it started
// has returned. The bool reports whether the edge answered the accept stream
// with 200.
func (m *sessionMux) serve(conn net.Conn) (bool, error) {
	connCtx, cancel := context.WithCancel(m.ctx)
	// The watcher closes the conn when serve returns or the mux's own context
	// ends (only stop cancels it), not on the control session's context.
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		<-connCtx.Done()
		_ = conn.Close()
	}()
	var opens sync.WaitGroup
	defer func() {
		cancel()
		<-watcherDone
		opens.Wait()
	}()

	cc, err := newSessionClientConn(connCtx, conn)
	if err != nil {
		return false, fmt.Errorf("session mux client: %w", err)
	}
	defer cc.Close()

	req, err := newSessionMuxRequest(connCtx, http.MethodPost, sessionAcceptPath, nil)
	if err != nil {
		return false, err
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return false, fmt.Errorf("session accept stream: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("session accept stream: edge answered %d", resp.StatusCode)
	}
	clip := newClipboardClient(connCtx, cc)
	m.clip.Store(clip)
	defer m.clip.CompareAndSwap(clip, nil)
	if m.signer != nil {
		// Unpublished before cc closes; a request already holding the client
		// fails as a transport error once the conn is gone.
		rc := newRecordingClient(connCtx, cc, m.signer)
		m.rec.Store(rc)
		defer m.rec.CompareAndSwap(rc, nil)
		m.handler.RecordingClientUp()
	}

	slots := make(chan struct{}, maxSessionOpens)
	var length [4]byte
	var notice [sessionNoticeLen]byte
	for {
		if _, err := io.ReadFull(resp.Body, length[:]); err != nil {
			return true, fmt.Errorf("session accept stream: %w", err)
		}
		if n := binary.BigEndian.Uint32(length[:]); n != sessionNoticeLen {
			return true, fmt.Errorf("session accept stream: notice length %d, want %d", n, sessionNoticeLen)
		}
		if _, err := io.ReadFull(resp.Body, notice[:]); err != nil {
			return true, fmt.Errorf("session accept stream: %w", err)
		}
		var id [sessionIDLen]byte
		copy(id[:], notice[:sessionIDLen])
		serial := binary.BigEndian.Uint64(notice[sessionIDLen:])
		select {
		case slots <- struct{}{}:
		case <-connCtx.Done():
			return true, connCtx.Err()
		}
		opens.Add(1)
		go func() {
			defer opens.Done()
			defer func() { <-slots }()
			m.openSession(connCtx, cc, conn, id, serial)
		}()
	}
}

// openSession opens the session stream for one notice and hands it to the
// handler. The stream is always opened, so the edge sees every refusal on it.
func (m *sessionMux) openSession(ctx context.Context, cc *http.ClientConn, conn net.Conn, id [sessionIDLen]byte, serial uint64) {
	streamCtx, cancel := context.WithCancel(ctx)
	reqBody, bodyWriter := io.Pipe()
	req, err := newSessionMuxRequest(streamCtx, http.MethodPost, sessionStreamPath, reqBody)
	if err != nil {
		cancel()
		_ = bodyWriter.CloseWithError(err)
		return
	}
	req.Header.Set(sessionIDHeader, hex.EncodeToString(id[:]))

	// A stalled open is cancelled at the deadline and frees its slot. A timer
	// that fired as the headers arrived still counts: the stream is reset.
	expired := time.AfterFunc(m.openTimeout, cancel)
	resp, err := cc.RoundTrip(req)
	if !expired.Stop() && err == nil {
		_ = resp.Body.Close()
		err = context.DeadlineExceeded
	}
	if err != nil {
		cancel()
		_ = bodyWriter.CloseWithError(err)
		if ctx.Err() == nil {
			slog.Default().Debug("session stream open failed",
				slog.String("tunnel", m.label), slog.Any("error", err))
		}
		return
	}
	stream := &sessionStream{
		body:   resp.Body,
		writer: bodyWriter,
		cancel: cancel,
		local:  conn.LocalAddr(),
		remote: conn.RemoteAddr(),
	}
	if resp.StatusCode != http.StatusOK {
		_ = stream.Close()
		slog.Default().Debug("session stream refused by the edge",
			slog.String("tunnel", m.label), slog.Int("status", resp.StatusCode))
		return
	}
	if !m.handOver(stream, id, serial) {
		_ = stream.Close()
	}
}

// handOver starts Serve for stream unless stop has begun. The check and the
// Add are one critical section with stop's, so run's Wait covers every Serve.
func (m *sessionMux) handOver(stream net.Conn, id [sessionIDLen]byte, serial uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping {
		return false
	}
	m.served.Add(1)
	go func() {
		defer m.served.Done()
		defer stream.Close()
		m.handler.Serve(stream, id, serial)
		flushSessionStream(stream)
	}()
	return true
}

// sessionStreamFlushTimeout bounds how long a finished session stream waits
// for the edge to take its last bytes.
const sessionStreamFlushTimeout = 2 * time.Second

// flushSessionStream delivers what Serve wrote last, such as a refusal, before
// the deferred Close resets the stream: it half-closes and reads to EOF.
func flushSessionStream(stream net.Conn) {
	closer, ok := stream.(interface{ CloseWrite() error })
	if !ok {
		return
	}
	_ = closer.CloseWrite()
	_ = stream.SetReadDeadline(time.Now().Add(sessionStreamFlushTimeout))
	_, _ = io.Copy(io.Discard, stream)
}

// newSessionMuxRequest builds a request on the session mux. A nil body sends
// END_STREAM on the headers.
func newSessionMuxRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://"+sessionMuxAuthority+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", sessionMuxUserAgent)
	return req, nil
}

// newSessionClientConn speaks HTTP/2 with prior knowledge over the bound conn
// as the client, with the session mux's bounds.
func newSessionClientConn(ctx context.Context, conn net.Conn) (*http.ClientConn, error) {
	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	tr := &http.Transport{
		Protocols: &protocols,
		HTTP2: &http.HTTP2Config{
			MaxReadFrameSize:              sessionMuxMaxFrame,
			MaxReceiveBufferPerStream:     sessionMuxStreamWindow,
			MaxReceiveBufferPerConnection: sessionMuxConnWindow,
			SendPingTimeout:               sessionMuxPingInterval,
			PingTimeout:                   sessionMuxPingTimeout,
			WriteByteTimeout:              sessionMuxPingTimeout,
		},
		MaxResponseHeaderBytes: sessionMuxMaxHeaderBytes,
		// Session bytes are end-to-end encrypted and never compress.
		DisableCompression: true,
		// The conn is already dialed and bound. plainConn hides the carrier's
		// TLS state, which is not an h2 ALPN.
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return plainConn{conn}, nil
		},
	}
	return tr.NewClientConn(ctx, "http", sessionMuxAuthority+":80")
}

// sessionStream is one session stream as a net.Conn: Read from the response
// body, Write to the request body.
//
// Not net.Conn deadline semantics: an expired deadline closes the stream, and
// every later call fails with os.ErrDeadlineExceeded. Close resets the stream
// at once; CloseWrite half-closes it (END_STREAM after every written byte), so
// a caller that must deliver its last bytes calls CloseWrite and reads to EOF
// before Close.
type sessionStream struct {
	body   io.ReadCloser
	writer *io.PipeWriter
	cancel context.CancelFunc
	local  net.Addr
	remote net.Addr

	closeOnce sync.Once
	expired   atomic.Bool

	timerMu    sync.Mutex
	readTimer  *time.Timer
	writeTimer *time.Timer
}

func (s *sessionStream) Read(p []byte) (int, error) {
	n, err := s.body.Read(p)
	if err != nil && s.expired.Load() {
		err = os.ErrDeadlineExceeded
	}
	return n, err
}

func (s *sessionStream) Write(p []byte) (int, error) {
	n, err := s.writer.Write(p)
	if err != nil && s.expired.Load() {
		err = os.ErrDeadlineExceeded
	}
	return n, err
}

// CloseWrite ends the request body; the edge reads EOF after the last byte.
func (s *sessionStream) CloseWrite() error { return s.writer.Close() }

func (s *sessionStream) Close() error {
	s.closeOnce.Do(func() {
		s.timerMu.Lock()
		stopTimer(s.readTimer)
		stopTimer(s.writeTimer)
		s.timerMu.Unlock()
		_ = s.writer.CloseWithError(net.ErrClosed)
		s.cancel()
		_ = s.body.Close()
	})
	return nil
}

func (s *sessionStream) LocalAddr() net.Addr  { return s.local }
func (s *sessionStream) RemoteAddr() net.Addr { return s.remote }

func (s *sessionStream) SetDeadline(t time.Time) error {
	s.timerMu.Lock()
	defer s.timerMu.Unlock()
	s.readTimer = s.armLocked(s.readTimer, t)
	s.writeTimer = s.armLocked(s.writeTimer, t)
	return nil
}

func (s *sessionStream) SetReadDeadline(t time.Time) error {
	s.timerMu.Lock()
	defer s.timerMu.Unlock()
	s.readTimer = s.armLocked(s.readTimer, t)
	return nil
}

func (s *sessionStream) SetWriteDeadline(t time.Time) error {
	s.timerMu.Lock()
	defer s.timerMu.Unlock()
	s.writeTimer = s.armLocked(s.writeTimer, t)
	return nil
}

// armLocked replaces timer with one that expires the stream at t; the zero
// time disarms it.
func (s *sessionStream) armLocked(timer *time.Timer, t time.Time) *time.Timer {
	stopTimer(timer)
	if t.IsZero() {
		return nil
	}
	return time.AfterFunc(time.Until(t), s.expire)
}

func (s *sessionStream) expire() {
	s.expired.Store(true)
	_ = s.Close()
}

func stopTimer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}

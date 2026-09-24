package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/localport/agent/internal/proto"
	"github.com/localport/agent/internal/transport"
)

// HTTP/2 flow control windows for data the edge sends. The net/http server
// default of 1 MiB per connection throttles concurrent uploads.
//
// 4 MiB per stream matches the net/http client default. 16 MiB per connection
// matches the grpc-go BDP estimator cap. Windows are limits, and memory is used
// only while the local service reads slower than the edge sends.
const (
	muxUploadBufferPerConnection = 16 << 20
	muxUploadBufferPerStream     = 4 << 20

	// Timeout for the bind exchange.
	muxBindTimeout = 10 * time.Second

	// muxIdleTimeout closes a connection the edge stopped using. It exceeds
	// the edge keepalive interval.
	muxIdleTimeout = 5 * time.Minute
)

// startMux starts the multiplexed data connection for the current session in
// the background and returns a function that stops it. The tunnel serves over
// dial-back meanwhile.
func (t *Tunnel) startMux(ctx context.Context) func() {
	if t.opts.DisableMux {
		return func() {}
	}

	t.mu.RLock()
	addr, session := t.edgeAddr, t.sessionID
	t.mu.RUnlock()

	muxCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	go func() {
		defer close(done)
		t.runMux(muxCtx, addr, session)
	}()

	return func() {
		cancel()
		<-done
	}
}

// runMux keeps a multiplexed connection up for the session. The first bind is
// attempted once, and on failure the tunnel stays on dial-back. A connection
// that bound and then dropped is retried.
func (t *Tunnel) runMux(ctx context.Context, addr, session string) {
	conn, err := t.dialAndBindMux(ctx, addr, session)
	if err != nil {
		// Debug level. The tunnel still serves over dial-back.
		slog.Default().Debug("multiplexed transport unavailable, using dial-back",
			slog.String("tunnel", t.opts.Label),
			slog.Any("error", err))
		return
	}

	for attempt := 0; ; attempt++ {
		t.serveConnUntilClosed(ctx, conn)
		if ctx.Err() != nil {
			return
		}

		slog.Default().Debug("multiplexed transport dropped, re-establishing",
			slog.String("tunnel", t.opts.Label))

		if !sleepCtx(ctx, muxRetryBackoff(attempt)) {
			return
		}

		conn, err = t.dialAndBindMux(ctx, addr, session)
		if err != nil {
			slog.Default().Debug("multiplexed transport could not be re-established, using dial-back",
				slog.String("tunnel", t.opts.Label),
				slog.Any("error", err))
			return
		}
		attempt = -1 // reset backoff after a successful bind
	}
}

// serveConnUntilClosed serves the connection and guarantees it is closed on the
// way out, including when the session is torn down while it sits idle. Closing
// is what ends serveMux, so teardown runs through the connection rather
// than through the server.
func (t *Tunnel) serveConnUntilClosed(ctx context.Context, conn net.Conn) {
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-stopped:
		}
	}()

	t.serveMux(conn)
	close(stopped)
	conn.Close()
}

// muxRetryBackoff spaces re-establishment attempts. It stays short because the
// tunnel serves over dial-back meanwhile, so the only cost of waiting is the
// optimisation being off a little longer.
func muxRetryBackoff(attempt int) time.Duration {
	const (
		base = 500 * time.Millisecond
		ceil = 30 * time.Second
	)
	if attempt < 0 {
		attempt = 0
	}
	if attempt > 16 {
		return ceil
	}
	if d := base << attempt; d < ceil {
		return d
	}
	return ceil
}

// sleepCtx waits for d, reporting false if the context ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// dialAndBindMux opens and binds the multiplexed data connection for a
// registered session. It authenticates with the token and the RegisterAck
// session id. Errors are not fatal to the tunnel.
func (t *Tunnel) dialAndBindMux(ctx context.Context, edgeAddr, sessionID string) (net.Conn, error) {
	if sessionID == "" {
		return nil, errors.New("mux bind: edge did not issue a session id")
	}

	// Dial with the transport the control connection uses, raw TLS or
	// WebSocket. The MuxBind frame identifies the connection to the edge.
	t.mu.RLock()
	dialer := t.dialer
	t.mu.RUnlock()
	if dialer == nil {
		return nil, errors.New("mux dial: control connection has not selected a transport")
	}

	host, port := transport.SplitHostPort(edgeAddr)
	conn, err := dialer.Dial(ctx, host, port)
	if err != nil {
		return nil, fmt.Errorf("mux dial (%s): %w", dialer.Kind(), err)
	}

	nonce, err := newNonce()
	if err != nil {
		conn.Close()
		return nil, err
	}

	pc := proto.NewConn(conn)
	bind := &proto.MuxBindPayload{
		Token:     t.opts.Token,
		SessionID: sessionID,
		Timestamp: time.Now().Unix(),
		Nonce:     nonce,
	}
	if err := pc.SendMuxBind(bind); err != nil {
		conn.Close()
		return nil, fmt.Errorf("mux bind send: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(muxBindTimeout)); err != nil {
		conn.Close()
		return nil, err
	}
	msgType, body, err := pc.Recv()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("mux bind response: %w", err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}

	if msgType != proto.MsgMuxBindAck {
		conn.Close()
		return nil, fmt.Errorf("mux bind: unexpected %s from edge", msgType)
	}
	ack, err := proto.ParseMuxBindAck(body)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("mux bind ack: %w", err)
	}
	if !ack.Success {
		conn.Close()
		return nil, fmt.Errorf("mux bind refused: %s", ack.Error)
	}

	return conn, nil
}

// serveMux serves streams until the connection drops.
func (t *Tunnel) serveMux(conn net.Conn) {
	handler := &muxServer{
		dialTarget:   t.dialTarget,
		device:       t.IsDevice(),
		tracker:      t,
		totalIn:      &t.totalBytesIn,
		totalOut:     &t.totalBytesOut,
		newInspector: t.newInspectorFor,
		defaultProto: t.opts.Protocol,
	}

	closed := make(chan struct{})
	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	server := &http.Server{
		Handler:   handler,
		Protocols: &protocols,
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams:          maxConcurrentDataConns,
			MaxReceiveBufferPerConnection: muxUploadBufferPerConnection,
			MaxReceiveBufferPerStream:     muxUploadBufferPerStream,
		},
		// Close a half-open connection. The edge pings idle connections.
		IdleTimeout: muxIdleTimeout,
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				close(closed)
			}
		},
	}
	// Serve returns once the listener is exhausted. The connection is served
	// on its own goroutine until it closes. Any other error means it was
	// never accepted.
	if err := server.Serve(&muxListener{conn: plainConn{conn}}); !errors.Is(err, errMuxListenerDone) {
		_ = conn.Close()
		return
	}
	<-closed
}

// plainConn hides the TLS state of the control carrier. The mux speaks HTTP/2
// with prior knowledge inside it, and net/http would otherwise route the
// connection by the carrier's ALPN.
type plainConn struct{ net.Conn }

// muxListener hands one connection to http.Server.
type muxListener struct {
	conn net.Conn
	once sync.Once
}

var errMuxListenerDone = errors.New("mux listener: connection already served")

func (l *muxListener) Accept() (net.Conn, error) {
	var conn net.Conn
	l.once.Do(func() { conn = l.conn })
	if conn == nil {
		return nil, errMuxListenerDone
	}
	return conn, nil
}

func (l *muxListener) Close() error   { return nil }
func (l *muxListener) Addr() net.Addr { return l.conn.LocalAddr() }

// newStreamID labels a stream in the live connection view. The dial-back path
// takes its id from the edge's NewConnection frame; a stream has no such frame,
// so the agent mints one. It is display-only and never leaves the process.
func newStreamID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "stream"
	}
	return "mux-" + hex.EncodeToString(b[:])
}

// Begin adds a stream to the live connection view used by proxyData. Closing
// localConn ends both copies, which is how a closed port cuts a mux stream.
func (t *Tunnel) Begin(remote string, target connTarget, localConn net.Conn) *activeConn {
	local := t.opts.Local
	if t.IsDevice() {
		local = net.JoinHostPort(t.opts.Host, strconv.Itoa(int(target.port)))
	}
	ac := &activeConn{
		id:        newStreamID(),
		local:     local,
		localConn: localConn,
		remote:    remote,
		port:      target.port,
		consumer:  target.consumer,
		startedAt: time.Now(),
	}
	t.addActiveConn(ac)
	t.totalConns.Add(1)

	if h := t.opts.Handler; h != nil {
		h.OnDataConn(t.opts.Label, DataConnInfo{
			ConnID:   ac.id,
			Target:   local,
			Remote:   remote,
			Consumer: target.consumer,
			Port:     target.port,
		})
	}
	return ac
}

// End removes a finished stream from the live view. Bytes were counted during
// the copy. The caller filters err through firstCopyError.
func (t *Tunnel) End(ac *activeConn, err error) {
	if ac == nil {
		return
	}
	t.removeActiveConn(ac.id)

	if h := t.opts.Handler; h != nil {
		h.OnDataClose(t.opts.Label, ac.id, ac.local, ac.remote,
			ac.bytesIn.Load(), ac.bytesOut.Load(), time.Since(ac.startedAt), err)
	}
}

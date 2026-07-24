package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/localport/agent/internal/proto"
	"github.com/localport/agent/internal/transport"

	"golang.org/x/net/http2"
)

// Flow control for the multiplexed connection.
//
// These are the windows the edge may fill when sending us a visitor's request
// body. The library default is 1 MiB per connection shared by every stream,
// which throttles concurrent uploads badly once a handful of transfers overlap.
// That default has been observed elsewhere to cut a single transfer to a
// fraction of its unmuxed speed. Raising the connection window and giving each
// stream a real share of it keeps a muxed transfer indistinguishable from a
// dialed one.
const (
	muxUploadBufferPerConnection = 16 << 20
	muxUploadBufferPerStream     = 4 << 20

	// Concurrency ceiling for streams the edge may have open at once. Generous
	// for a tunnel, and bounded so a misbehaving edge cannot exhaust local file
	// descriptors through the local service.
	muxMaxConcurrentStreams = 512

	// Bind exchange bound. A silent edge must not hold the connection.
	muxBindTimeout = 10 * time.Second

	// muxIdleTimeout closes a connection the edge has stopped using. It is
	// longer than the edge's keepalive interval so a healthy idle tunnel is
	// never torn down by it.
	muxIdleTimeout = 5 * time.Minute
)

// startMux brings up the multiplexed data connection for the current session
// and returns a function that tears it down.
//
// It runs in the background because the tunnel is already serving over
// dial-back by the time it is called: a slow bind delays nothing, and a refused
// one costs nothing. That is what makes multiplexing an optimisation rather
// than a dependency.
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

// runMux keeps a multiplexed connection up for as long as the session lasts.
//
// The first bind gets ONE attempt. A bind that fails usually means the network
// or the edge will not have it, and retrying would be a slower path to the
// dial-back the tunnel is already using.
//
// A connection that bound successfully and then DROPPED is a different case: it
// worked a moment ago, so the cause is a blip, an idle middlebox, or an edge
// socket going away. Without re-establishing, one dropped connection would cost
// the session its multiplexing for however many hours it runs.
func (t *Tunnel) runMux(ctx context.Context, addr, session string) {
	conn, err := t.dialAndBindMux(ctx, addr, session)
	if err != nil {
		// Debug, not an error event: the tunnel serves either way, and
		// surfacing this to the user would be alarming without being
		// actionable. Same channel the transport probe reports on.
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
		attempt = -1 // reset the backoff once a bind succeeds
	}
}

// serveConnUntilClosed serves the connection and guarantees it is closed on the
// way out, including when the session is torn down while it sits idle. Closing
// is what unblocks ServeConn, so teardown runs through the connection rather
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

// dialAndBindMux establishes the multiplexed data connection for a registered
// session.
//
// The connection is separate from the control connection and is authenticated
// on its own: the token proves which tunnel, the session id from the RegisterAck
// names which live client these streams belong to. Failure at any step is
// returned to the caller and is NOT fatal: the tunnel keeps working on
// dial-back, which is the point of keeping both paths.
func (t *Tunnel) dialAndBindMux(ctx context.Context, edgeAddr, sessionID string) (net.Conn, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("mux bind: edge did not issue a session id")
	}

	// Reuse the carrier the control connection already found through the
	// firewall. A second Dial on the cached dialer gives a fresh connection over
	// the same transport (raw TLS, or WebSocket through an inspecting proxy), so
	// the mux works on exactly the networks the tunnel works on. That is the
	// whole reason it reuses the carrier instead of dialing its own, and it is why
	// the mux carries no ALPN of its own: the
	// MuxBind frame below is what tells the edge this connection is a mux.
	t.mu.RLock()
	dialer := t.dialer
	t.mu.RUnlock()
	if dialer == nil {
		return nil, fmt.Errorf("mux dial: control connection has not selected a transport")
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
		ClientID:  t.clientID,
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

// serveMux carries streams until the connection drops.
func (t *Tunnel) serveMux(conn net.Conn) {
	server := &http2.Server{
		MaxConcurrentStreams:         muxMaxConcurrentStreams,
		MaxUploadBufferPerConnection: muxUploadBufferPerConnection,
		MaxUploadBufferPerStream:     muxUploadBufferPerStream,
		// The edge pings an idle connection; answering is automatic. This bounds
		// how long a half-open connection survives on our side.
		IdleTimeout: muxIdleTimeout,
	}

	handler := &muxServer{
		dialLocal: func() (net.Conn, error) {
			return net.DialTimeout("tcp", t.opts.Local, dialTimeout)
		},
		tracker:      t,
		totalIn:      &t.totalBytesIn,
		totalOut:     &t.totalBytesOut,
		newInspector: t.newRequestInspector,
	}

	// ServeConn blocks for the life of the connection.
	server.ServeConn(conn, &http2.ServeConnOpts{Handler: handler})
}

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

// Begin registers a stream in the same connection view proxyData feeds, so the
// live list and its counters are identical whichever transport carried the
// traffic. Without this a muxed tunnel would show no connections at all.
func (t *Tunnel) Begin(remote string) *activeConn {
	ac := &activeConn{
		id:        newStreamID(),
		local:     t.opts.Local,
		remote:    remote,
		startedAt: time.Now(),
	}
	t.addActiveConn(ac)
	t.totalConns.Add(1)

	if h := t.opts.Handler; h != nil {
		h.OnDataConn(t.opts.Label, ac.id, t.opts.Local, remote)
	}
	return ac
}

// End removes a finished stream from the live view. Byte counts were folded in
// as they moved, so nothing is added here.
func (t *Tunnel) End(ac *activeConn, err error) {
	if ac == nil {
		return
	}
	t.removeActiveConn(ac.id)

	if h := t.opts.Handler; h != nil {
		h.OnDataClose(t.opts.Label, ac.id, t.opts.Local, ac.remote,
			ac.bytesIn.Load(), ac.bytesOut.Load(), time.Since(ac.startedAt), ignoreClosed(err))
	}
}

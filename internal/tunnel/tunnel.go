package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/localport/agent/internal/proto"
	"github.com/localport/agent/internal/transport"
)

const (
	dialTimeout         = 10 * time.Second
	registrationTimeout = 10 * time.Second
	heartbeatInterval   = 30 * time.Second
	sessionDrainTimeout = 5 * time.Second
	maxBackoff          = 30 * time.Second
	maxRedirectHops     = 5
	receivePollInterval = 100 * time.Millisecond
)

type State int32

const (
	StateIdle State = iota
	StateConnecting
	StateRegistering
	StateActive
	StateReconnecting
	StateStopped
)

func (s State) String() string {
	switch s {
	case StateIdle:
		return "idle"
	case StateConnecting:
		return "connecting"
	case StateRegistering:
		return "registering"
	case StateActive:
		return "active"
	case StateReconnecting:
		return "reconnecting"
	case StateStopped:
		return "stopped"
	}
	return "unknown"
}

// Info is the registration result returned by the edge.
type Info struct {
	TunnelID   string
	TunnelName string
	Region     string
	EdgeAddr   string
	PublicURL  string
	URLs       []string
	Subdomain  string
	Port       uint16
	Mode       string
	Protocol   string
	MTLS       *proto.MTLSInfo
}

// EventHandler observes tunnel lifecycle events. A nil handler is allowed.
type EventHandler interface {
	OnStateChange(label string, from, to State)
	OnConnected(label string, info Info)
	OnDisconnected(label string, err error)
	OnError(label string, err error)
	OnDataConn(label, connID, local, remote string)
	OnDataClose(label, connID, local, remote string, bytesIn, bytesOut int64, dur time.Duration, err error)
	OnRedirect(label, from, to string)
	OnShutdownPolicy(label, reason, code string, limit proto.LimitType, retryable bool)
}

// ActiveConn is a snapshot of one live edge↔local proxy. The byte counts
// are loaded from atomics, so a snapshot taken mid-transfer reflects the
// bytes seen up to that instant.
type ActiveConn struct {
	ID        string
	Local     string
	Remote    string
	StartedAt time.Time
	BytesIn   int64
	BytesOut  int64
}

// Stats is a snapshot of tunnel-lifetime counters.
type Stats struct {
	BytesIn           int64
	BytesOut          int64
	ConnectionsServed int64
}

type Options struct {
	Label      string
	Token      string
	Edge       string
	Local      string
	Protocol   string
	ClientName string
	Handler    EventHandler

	// Transport tunes the agent's edge transport (raw vs ws probe order,
	// dial timeout, WS path). The zero value uses Phase 1 secure defaults:
	// TLS 1.3, full server-cert verification, no insecure fallback.
	Transport transport.Options
}

type Tunnel struct {
	opts Options

	state    atomic.Int32
	closing  atomic.Bool
	clientID string

	mu       sync.RWMutex
	conn     *proto.Conn
	raw      net.Conn
	edgeAddr string
	info     Info

	terminalMu  sync.Mutex
	terminalErr error

	// dialer is the transport selected by the most recent Probe. Reused
	// for data dial-backs within the same session and reset on reconnect
	// so the next session re-probes.
	dialer transport.Dialer

	acMu        sync.RWMutex
	activeConns map[string]*activeConn

	totalBytesIn  atomic.Int64
	totalBytesOut atomic.Int64
	totalConns    atomic.Int64

	shutdown     chan struct{}
	disconnected chan struct{}
	wg           sync.WaitGroup
}

// activeConn is the internal record for one live edge↔local proxy. Byte
// counters are written from the two io.Copy goroutines and read from the
// UI snapshot path; atomics avoid lock contention on the hot path.
type activeConn struct {
	id        string
	local     string
	remote    string
	startedAt time.Time
	bytesIn   atomic.Int64
	bytesOut  atomic.Int64

	edge      net.Conn
	localConn net.Conn
}

func New(opts Options) *Tunnel {
	if opts.ClientName == "" {
		opts.ClientName, _ = os.Hostname()
	}
	if opts.Protocol == "" {
		opts.Protocol = "http"
	}
	t := &Tunnel{
		opts:         opts,
		edgeAddr:     opts.Edge,
		clientID:     newClientID(),
		activeConns:  make(map[string]*activeConn),
		shutdown:     make(chan struct{}),
		disconnected: make(chan struct{}),
	}
	t.state.Store(int32(StateIdle))
	return t
}

// Run drives the connect/register/serve loop until Stop or ctx cancellation.
// It returns nil on a clean stop and the registration error if the edge
// refuses the tunnel non-retryably.
func (t *Tunnel) Run(ctx context.Context) error {
	attempt := 0
	for {
		t.mu.Lock()
		t.disconnected = make(chan struct{})
		t.mu.Unlock()
		t.closing.Store(false)

		t.setState(StateConnecting)

		if err := t.connect(ctx); err != nil {
			if t.cancelled(ctx) {
				return t.consumeTerminalError()
			}
			var regErr *RegistrationError
			if errors.As(err, &regErr) && !regErr.Retryable {
				t.setState(StateStopped)
				t.emitShutdown(regErr.Message, regErr.Code, regErr.LimitType, false)
				return regErr
			}
			t.emitError(err)
			attempt++
			t.setState(StateReconnecting)
			if !t.wait(ctx, backoffFor(attempt)) {
				return nil
			}
			continue
		}

		attempt = 0
		t.setState(StateActive)
		t.emitConnected()

		t.runSession(ctx)

		if t.cancelled(ctx) {
			return t.consumeTerminalError()
		}

		t.closeConn()
		t.emitDisconnected(nil)

		attempt++
		t.setState(StateReconnecting)
		if !t.wait(ctx, backoffFor(attempt)) {
			return nil
		}
	}
}

func (t *Tunnel) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	safeClose(t.shutdown)
	safeClose(t.disconnected)
}

func (t *Tunnel) CurrentState() State { return State(t.state.Load()) }

func (t *Tunnel) Label() string { return t.opts.Label }

// Stats returns the cumulative byte and connection counters.
func (t *Tunnel) Stats() Stats {
	return Stats{
		BytesIn:           t.totalBytesIn.Load(),
		BytesOut:          t.totalBytesOut.Load(),
		ConnectionsServed: t.totalConns.Load(),
	}
}

// ActiveConnections returns a snapshot of currently-open proxy connections.
func (t *Tunnel) ActiveConnections() []ActiveConn {
	t.acMu.RLock()
	defer t.acMu.RUnlock()
	out := make([]ActiveConn, 0, len(t.activeConns))
	for _, ac := range t.activeConns {
		out = append(out, ActiveConn{
			ID:        ac.id,
			Local:     ac.local,
			Remote:    ac.remote,
			StartedAt: ac.startedAt,
			BytesIn:   ac.bytesIn.Load(),
			BytesOut:  ac.bytesOut.Load(),
		})
	}
	return out
}

func (t *Tunnel) addActiveConn(ac *activeConn) {
	t.acMu.Lock()
	t.activeConns[ac.id] = ac
	t.acMu.Unlock()
}

func (t *Tunnel) removeActiveConn(id string) {
	t.acMu.Lock()
	delete(t.activeConns, id)
	t.acMu.Unlock()
}

func (t *Tunnel) closeActiveConns() {
	t.acMu.RLock()
	defer t.acMu.RUnlock()
	for _, ac := range t.activeConns {
		if ac.edge != nil {
			_ = ac.edge.Close()
		}
		if ac.localConn != nil {
			_ = ac.localConn.Close()
		}
	}
}

// connect dials the edge and exchanges Register / RegisterAck, following
// up to maxRedirectHops redirects to another edge.
func (t *Tunnel) connect(ctx context.Context) error {
	addr := t.edgeAddr

	dialers := transport.DefaultDialers(t.opts.Transport)
	budget := t.opts.Transport.DialTimeout
	if budget == 0 {
		budget = 2 * time.Second
	}

	for range maxRedirectHops {
		raw, chosen, err := transport.Probe(ctx, addr, budget, dialers, slog.Default())
		if err != nil {
			return fmt.Errorf("connect %s: %w", addr, err)
		}

		pc := proto.NewConn(raw)
		t.setState(StateRegistering)

		nonce, err := newNonce()
		if err != nil {
			raw.Close()
			return err
		}
		reg := &proto.RegisterPayload{
			Token:      t.opts.Token,
			Protocol:   t.opts.Protocol,
			ClientID:   t.clientID,
			ClientName: t.opts.ClientName,
			Timestamp:  time.Now().Unix(),
			Nonce:      nonce,
		}
		if err := pc.SendRegister(reg); err != nil {
			raw.Close()
			return fmt.Errorf("send register: %w", err)
		}

		raw.SetReadDeadline(time.Now().Add(registrationTimeout))
		msgType, body, err := pc.Recv()
		raw.SetReadDeadline(time.Time{})
		if err != nil {
			raw.Close()
			return fmt.Errorf("register response: %w", err)
		}

		switch msgType {
		case proto.MsgRegisterAck:
			ack, err := proto.ParseRegisterAck(body)
			if err != nil {
				raw.Close()
				return fmt.Errorf("parse ack: %w", err)
			}
			if !ack.Success {
				raw.Close()
				return registrationErrorFrom(ack)
			}
			t.mu.Lock()
			t.raw = raw
			t.conn = pc
			t.edgeAddr = addr
			t.dialer = chosen
			t.info = Info{
				TunnelID:   ack.TunnelID,
				TunnelName: ack.TunnelName,
				Region:     ack.Region,
				EdgeAddr:   addr,
				PublicURL:  ack.PublicURL,
				URLs:       ack.URLs,
				Subdomain:  ack.Subdomain,
				Port:       ack.Port,
				Mode:       ack.Mode,
				Protocol:   ack.Protocol,
				MTLS:       ack.MTLS,
			}
			t.mu.Unlock()
			return nil

		case proto.MsgRedirect:
			rd, err := proto.ParseRedirect(body)
			raw.Close()
			if err != nil {
				return fmt.Errorf("parse redirect: %w", err)
			}
			if !allowedRedirectHost(rd.EdgeAddr) {
				return fmt.Errorf("refusing redirect to untrusted host %q", sanitizeAddr(rd.EdgeAddr))
			}
			if h := t.opts.Handler; h != nil {
				h.OnRedirect(t.opts.Label, addr, rd.EdgeAddr)
			}
			addr = rd.EdgeAddr

		case proto.MsgError:
			ep, _ := proto.ParseError(body)
			raw.Close()
			if ep != nil {
				return fmt.Errorf("edge error [%s]: %s", ep.Code, ep.Message)
			}
			return errors.New("edge returned error")

		default:
			raw.Close()
			return fmt.Errorf("unexpected message during register: %s", msgType)
		}
	}
	return fmt.Errorf("too many redirects (>%d)", maxRedirectHops)
}

func (t *Tunnel) runSession(ctx context.Context) {
	t.wg.Add(2)
	go t.heartbeatLoop()
	go t.receiveLoop()

	select {
	case <-ctx.Done():
	case <-t.shutdown:
	case <-t.disconnected:
	}

	// Tear down in-flight proxy sockets so their copy loops return now
	t.closeActiveConns()

	done := make(chan struct{})
	go func() { t.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(sessionDrainTimeout):
	}
}

func (t *Tunnel) heartbeatLoop() {
	defer t.wg.Done()
	tick := time.NewTicker(heartbeatInterval)
	defer tick.Stop()

	for {
		select {
		case <-t.shutdown:
			return
		case <-t.disconnected:
			return
		case <-tick.C:
			c := t.snapshotConn()
			if c == nil {
				return
			}
			if err := c.SendHeartbeat(); err != nil {
				t.signalDisconnected()
				return
			}
		}
	}
}

func (t *Tunnel) receiveLoop() {
	defer t.wg.Done()
	for {
		select {
		case <-t.shutdown:
			return
		case <-t.disconnected:
			return
		default:
		}

		// start reading from a newly-attached connection that belongs to
		// the next attempt.
		if t.closing.Load() {
			return
		}

		raw, pc := t.snapshotConnPair()
		if raw == nil || pc == nil {
			return
		}

		raw.SetReadDeadline(time.Now().Add(receivePollInterval))
		msgType, body, err := pc.Recv()
		raw.SetReadDeadline(time.Time{})
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			t.signalDisconnected()
			return
		}
		t.dispatch(msgType, body)
	}
}

func (t *Tunnel) dispatch(msgType proto.MessageType, body []byte) {
	switch msgType {
	case proto.MsgNewConnection:
		nc, err := proto.ParseNewConnection(body)
		if err != nil {
			return
		}
		t.wg.Add(1)

		go t.proxyData(nc.ConnectionID, sanitizeAddr(nc.RemoteAddr))

	case proto.MsgHeartbeat:
		hb, _ := proto.ParseHeartbeat(body)
		if hb == nil {
			return
		}
		if c := t.snapshotConn(); c != nil {
			_ = c.SendHeartbeatAck(hb.Timestamp)
		}

	case proto.MsgHeartbeatAck, proto.MsgSetActive:
		// nothing to do; edge liveness / dispatch hints

	case proto.MsgShutdown:
		sd, _ := proto.ParseShutdown(body)
		if sd != nil && sd.Retryable != nil && !*sd.Retryable {
			reason := sd.Reason
			if reason == "" {
				reason = "edge closed the tunnel"
			}
			t.setTerminalError(&RegistrationError{
				Message:   reason,
				Code:      sd.Code,
				LimitType: sd.LimitType,
			})
			t.emitShutdown(reason, sd.Code, sd.LimitType, false)
			t.Stop()
			return
		}
		t.signalDisconnected()

	case proto.MsgError:
		ep, _ := proto.ParseError(body)
		if ep != nil {
			t.emitError(fmt.Errorf("[%s] %s", ep.Code, ep.Message))
		}
	}
}

const edgeBaseDomain = "localport.dev"

func allowedRedirectHost(addr string) bool {
	host, _ := transport.SplitHostPort(addr)
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	return host == edgeBaseDomain || strings.HasSuffix(host, "."+edgeBaseDomain)
}

func sanitizeAddr(s string) string {
	return strings.Map(func(r rune) rune {
		if r == 0x7f || r < 0x20 || (r >= 0x80 && r <= 0x9f) {
			return -1
		}
		return r
	}, s)
}

func (t *Tunnel) proxyData(connID, remote string) {
	defer t.wg.Done()

	t.mu.RLock()
	addr := t.edgeAddr
	dialer := t.dialer
	t.mu.RUnlock()

	ac := &activeConn{
		id:        connID,
		local:     t.opts.Local,
		remote:    remote,
		startedAt: time.Now(),
	}
	closeEvt := func(in, out int64, err error) {
		if h := t.opts.Handler; h != nil {
			h.OnDataClose(t.opts.Label, connID, t.opts.Local, remote, in, out, time.Since(ac.startedAt), err)
		}
	}
	if dialer == nil {
		closeEvt(0, 0, fmt.Errorf("data dial: no transport selected (control connection not established)"))
		return
	}

	host, port := transport.SplitHostPort(addr)
	dialCtx, cancelDial := context.WithTimeout(context.Background(), dialTimeout)
	edge, err := dialer.Dial(dialCtx, host, port)
	cancelDial()
	if err != nil {
		closeEvt(0, 0, fmt.Errorf("data dial (%s): %w", dialer.Kind(), err))
		return
	}
	pc := proto.NewConn(edge)
	if err := pc.SendConnectionReady(&proto.ConnectionReadyPayload{ConnectionID: connID}); err != nil {
		edge.Close()
		closeEvt(0, 0, err)
		return
	}

	local, err := net.DialTimeout("tcp", t.opts.Local, dialTimeout)
	if err != nil {
		edge.Close()
		closeEvt(0, 0, fmt.Errorf("local dial %s: %w", t.opts.Local, err))
		return
	}

	ac.edge = edge
	ac.localConn = local
	t.addActiveConn(ac)
	t.totalConns.Add(1)
	defer t.removeActiveConn(connID)

	if h := t.opts.Handler; h != nil {
		h.OnDataConn(t.opts.Label, connID, t.opts.Local, remote)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		copyWithCounters(local, edge, &ac.bytesIn, &t.totalBytesIn)
		if cw, ok := local.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		copyWithCounters(edge, local, &ac.bytesOut, &t.totalBytesOut)
		if cw, ok := edge.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
	edge.Close()
	local.Close()

	closeEvt(ac.bytesIn.Load(), ac.bytesOut.Load(), nil)
}

// copyWithCounters streams src→dst and accumulates each successful write
// into every counter atomically. Per-conn and tunnel-total counters stay
// in sync because both see the same bytes the same moment.
func copyWithCounters(dst io.Writer, src io.Reader, counters ...*atomic.Int64) {
	buf := make([]byte, 32*1024)
	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			if nw > 0 {
				for _, c := range counters {
					c.Add(int64(nw))
				}
			}
			if werr != nil || nr != nw {
				return
			}
		}
		if rerr != nil {
			return
		}
	}
}

func (t *Tunnel) closeConn() {
	t.closing.Store(true)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil {
		_ = t.conn.SendShutdown("agent disconnecting")
	}
	if t.raw != nil {
		_ = t.raw.Close()
		t.raw = nil
	}
	t.conn = nil
}

func (t *Tunnel) signalDisconnected() {
	t.mu.Lock()
	defer t.mu.Unlock()
	safeClose(t.disconnected)
}

func (t *Tunnel) setState(s State) {
	// Once stopped, never transition back to a transient state. This keeps
	// late-arriving events from re-arming a tunnel that should stay dead.
	if State(t.state.Load()) == StateStopped && s != StateStopped {
		return
	}
	old := State(t.state.Swap(int32(s)))
	if old != s {
		if h := t.opts.Handler; h != nil {
			h.OnStateChange(t.opts.Label, old, s)
		}
	}
}

func (t *Tunnel) setTerminalError(err error) {
	t.terminalMu.Lock()
	defer t.terminalMu.Unlock()
	if t.terminalErr == nil {
		t.terminalErr = err
	}
}

func (t *Tunnel) consumeTerminalError() error {
	t.terminalMu.Lock()
	defer t.terminalMu.Unlock()
	return t.terminalErr
}

func (t *Tunnel) snapshotConn() *proto.Conn {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.conn
}

func (t *Tunnel) snapshotConnPair() (net.Conn, *proto.Conn) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.raw, t.conn
}

func (t *Tunnel) emitConnected() {
	if h := t.opts.Handler; h != nil {
		h.OnConnected(t.opts.Label, t.info)
	}
}
func (t *Tunnel) emitDisconnected(err error) {
	if h := t.opts.Handler; h != nil {
		h.OnDisconnected(t.opts.Label, err)
	}
}
func (t *Tunnel) emitError(err error) {
	if h := t.opts.Handler; h != nil {
		h.OnError(t.opts.Label, err)
	}
}
func (t *Tunnel) emitShutdown(reason, code string, limit proto.LimitType, retryable bool) {
	if h := t.opts.Handler; h != nil {
		h.OnShutdownPolicy(t.opts.Label, reason, code, limit, retryable)
	}
}

func (t *Tunnel) cancelled(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	case <-t.shutdown:
		return true
	default:
		return false
	}
}

func (t *Tunnel) wait(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-t.shutdown:
		return false
	case <-time.After(d):
		return true
	}
}

// backoffFor returns a 1.5^(n-1) second delay capped at maxBackoff with
// up to 25% jitter added on top.
func backoffFor(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	base := time.Duration(float64(time.Second) * math.Pow(1.5, float64(attempt-1)))
	base = min(base, maxBackoff)
	return base + jitter(base/4)
}

func jitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	var b [1]byte
	_, _ = rand.Read(b[:])
	return time.Duration(int(b[0])) * max / 256
}

// RegistrationError is returned by Run when the edge refuses the tunnel.
// Callers can errors.As into it to inspect the limit type and decide
// whether to retry.
type RegistrationError struct {
	Message   string
	Code      string
	LimitType proto.LimitType
	Retryable bool
}

// Error renders the public, sanitized message supplied by the edge.
func (e *RegistrationError) Error() string {
	s := e.Message
	if e.LimitType != "" && e.LimitType != proto.LimitUnspecified {
		s += " [limit=" + string(e.LimitType) + "]"
	}
	return s
}

func registrationErrorFrom(ack *proto.RegisterAckPayload) *RegistrationError {
	msg := ack.Error
	if msg == "" {
		msg = "registration rejected"
	}
	retryable := true
	if ack.Retryable != nil {
		retryable = *ack.Retryable
	}
	return &RegistrationError{
		Message:   msg,
		Code:      ack.ErrorCode,
		LimitType: ack.LimitType,
		Retryable: retryable,
	}
}

func newClientID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "agent-" + hex.EncodeToString(b[:])
}

func newNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func safeClose(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
	}
}

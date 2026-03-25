package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/localport/agent/internal/proto"
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
	TunnelID  string
	PublicURL string
	URLs      []string
	Subdomain string
	Port      uint16
	Mode      string
	Protocol  string
}

// EventHandler observes tunnel lifecycle events. A nil handler is allowed.
type EventHandler interface {
	OnStateChange(label string, from, to State)
	OnConnected(label string, info Info)
	OnDisconnected(label string, err error)
	OnError(label string, err error)
	OnDataConn(label string, connID, local string)
	OnRedirect(label string, from, to string)
	OnShutdownPolicy(label string, code string, limit proto.LimitType, retryable bool)
}

type Options struct {
	Label      string
	Token      string
	Edge       string
	Local      string
	Protocol   string
	UseTLS     bool
	ClientName string
	Handler    EventHandler
}

type Tunnel struct {
	opts Options

	state    atomic.Int32
	clientID string

	mu       sync.RWMutex
	conn     *proto.Conn
	raw      net.Conn
	edgeAddr string
	info     Info

	shutdown     chan struct{}
	disconnected chan struct{}
	wg           sync.WaitGroup
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

		t.setState(StateConnecting)

		if err := t.connect(ctx); err != nil {
			if t.cancelled(ctx) {
				return nil
			}
			var regErr *RegistrationError
			if errors.As(err, &regErr) && !regErr.Retryable {
				t.setState(StateStopped)
				t.emitShutdown(regErr.Code, regErr.LimitType, false)
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
			return nil
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

// connect dials the edge and exchanges Register / RegisterAck, following
// up to maxRedirectHops redirects to another edge.
func (t *Tunnel) connect(ctx context.Context) error {
	addr := t.edgeAddr

	for range maxRedirectHops {
		raw, err := t.dial(ctx, addr)
		if err != nil {
			return fmt.Errorf("dial %s: %w", addr, err)
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
			t.info = Info{
				TunnelID:  ack.TunnelID,
				PublicURL: ack.PublicURL,
				URLs:      ack.URLs,
				Subdomain: ack.Subdomain,
				Port:      ack.Port,
				Mode:      ack.Mode,
				Protocol:  ack.Protocol,
			}
			t.mu.Unlock()
			return nil

		case proto.MsgRedirect:
			rd, err := proto.ParseRedirect(body)
			raw.Close()
			if err != nil {
				return fmt.Errorf("parse redirect: %w", err)
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
		go t.proxyData(nc.ConnectionID)

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
			t.emitShutdown(sd.Code, sd.LimitType, false)
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

func (t *Tunnel) proxyData(connID string) {
	defer t.wg.Done()

	t.mu.RLock()
	addr := t.edgeAddr
	t.mu.RUnlock()

	edge, err := t.dial(context.Background(), addr)
	if err != nil {
		t.emitError(fmt.Errorf("data dial: %w", err))
		return
	}
	pc := proto.NewConn(edge)
	if err := pc.SendConnectionReady(&proto.ConnectionReadyPayload{ConnectionID: connID}); err != nil {
		edge.Close()
		return
	}

	local, err := net.DialTimeout("tcp", t.opts.Local, dialTimeout)
	if err != nil {
		edge.Close()
		t.emitError(fmt.Errorf("local dial %s: %w", t.opts.Local, err))
		return
	}

	if h := t.opts.Handler; h != nil {
		h.OnDataConn(t.opts.Label, connID, t.opts.Local)
	}

	pipe(edge, local)
}

// pipe shuttles bytes between a and b until either side closes.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go halfPipe(&wg, a, b)
	go halfPipe(&wg, b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

func halfPipe(wg *sync.WaitGroup, dst, src net.Conn) {
	defer wg.Done()
	_, _ = io.Copy(dst, src)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// dial opens a TCP (or TLS over TCP) connection to addr.
func (t *Tunnel) dial(_ context.Context, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	return tls.DialWithDialer(d, "tcp", addr, &tls.Config{MinVersion: tls.VersionTLS12})
}

func (t *Tunnel) closeConn() {
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
	old := State(t.state.Swap(int32(s)))
	if old != s {
		if h := t.opts.Handler; h != nil {
			h.OnStateChange(t.opts.Label, old, s)
		}
	}
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
func (t *Tunnel) emitShutdown(code string, limit proto.LimitType, retryable bool) {
	if h := t.opts.Handler; h != nil {
		h.OnShutdownPolicy(t.opts.Label, code, limit, retryable)
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

func (e *RegistrationError) Error() string {
	s := e.Message
	if e.Code != "" {
		s += " [code=" + e.Code + "]"
	}
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

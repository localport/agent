package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/localport/agent/internal/proto"

	"golang.org/x/net/http2"
)

func TestAllowedRedirectHost(t *testing.T) {
	allow := []string{
		"connect.eu.localport.dev:443",
		"connect.us.localport.dev:443",
		"new-region.localport.dev:443",
		"localport.dev:443",
		"CONNECT.EU.LOCALPORT.DEV:443",  // case-insensitive
		"connect.eu.localport.dev.:443", // trailing dot FQDN
	}
	for _, a := range allow {
		if !allowedRedirectHost(a) {
			t.Errorf("expected %q to be allowed", a)
		}
	}
	deny := []string{
		"evil.com:443",
		"localport.dev.evil.com:443",
		"notlocalport.dev:443",
		"localhost:443",
		"127.0.0.1:443",
		"localport.dev.attacker.io:443",
		"",
		// Not hostnames. A suffix check alone would accept these.
		"evil.com/x.localport.dev:443",
		"evil.com\\x.localport.dev:443",
		"a\x1b[2J.eu.localport.dev:443",
		"user@e1.eu.localport.dev:443",
		"e1..eu.localport.dev:443",
		"-bad.eu.localport.dev:443",
		"bad-.eu.localport.dev:443",
		strings.Repeat("a", 64) + ".eu.localport.dev:443",
		".localport.dev:443",
	}
	for _, d := range deny {
		if allowedRedirectHost(d) {
			t.Errorf("expected %q to be refused", d)
		}
	}
}

func TestRegistrationErrorHidesCode(t *testing.T) {
	err := &RegistrationError{
		Message: "authentication token is invalid",
		Code:    "TK003",
	}
	if err.Code != "TK003" {
		t.Fatalf("Code field should be retained, got %q", err.Code)
	}
	if strings.Contains(err.Error(), "TK003") {
		t.Fatalf("Error() leaks the opaque code: %q", err.Error())
	}
	if err.Error() != "authentication token is invalid" {
		t.Fatalf("Error() = %q, want the bare sanitized message", err.Error())
	}
}

func TestRegistrationErrorRetryableDefaultsTrue(t *testing.T) {
	err := registrationErrorFrom(&proto.RegisterAckPayload{
		Success:   false,
		Error:     "rejected",
		ErrorCode: "TK003",
	})
	if !err.Retryable {
		t.Fatal("retryable should default to true when the field is unset")
	}
	if err.Code != "TK003" {
		t.Fatalf("Code = %q", err.Code)
	}
}

func TestRegistrationErrorRetryableExplicit(t *testing.T) {
	retryable := false
	err := registrationErrorFrom(&proto.RegisterAckPayload{
		Success:   false,
		Error:     "limit reached",
		ErrorCode: "BL007",
		Retryable: &retryable,
		LimitType: proto.LimitBandwidth,
	})
	if err.Retryable {
		t.Fatal("retryable should be false")
	}
	if err.LimitType != proto.LimitBandwidth {
		t.Fatalf("LimitType = %q", err.LimitType)
	}
}

func TestSNIForAddr(t *testing.T) {
	cases := []struct {
		edge, addr, want string
	}{
		// No redirect: original connect host verbatim.
		{"connect.us.localport.dev:443", "connect.us.localport.dev:443", "connect.us.localport.dev"},
		// Same-region redirect: SNI stays the zone connect host.
		{"connect.us.localport.dev:443", "e1.us.localport.dev:443", "connect.us.localport.dev"},
		// Cross-region redirect: SNI follows the TARGET zone.
		{"connect.us.localport.dev:443", "e1.eu.localport.dev:443", "connect.eu.localport.dev"},
		// Redirect to a zone-style host: idempotent derivation.
		{"connect.us.localport.dev:443", "connect.ap.localport.dev:443", "connect.ap.localport.dev"},
		// Dev / no zone to derive from: fall back to the original host.
		{"localhost:4443", "localhost:4443", "localhost"},
		{"localhost:4443", "otherhost:4443", "localhost"},
		// Original edge dialed by IP: never synthesize an SNI from it.
		{"203.0.113.5:443", "e1.eu.localport.dev:443", "203.0.113.5"},
	}
	for _, c := range cases {
		if got := sniForAddr(c.edge, c.addr); got != c.want {
			t.Errorf("sniForAddr(%q, %q) = %q, want %q", c.edge, c.addr, got, c.want)
		}
	}
}

func TestReceiveLoopIdleDisconnect(t *testing.T) {
	oldIdle := edgeIdleTimeout
	edgeIdleTimeout = 300 * time.Millisecond
	defer func() { edgeIdleTimeout = oldIdle }()

	// A pipe that stays open but never delivers a frame simulates a link
	// that died without an error: reads only ever time out.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	tn := New(Options{Token: "tok", Edge: "connect.eu.localport.dev:443", Local: "127.0.0.1:1"})
	tn.mu.Lock()
	tn.raw = a
	tn.conn = proto.NewConn(a)
	tn.mu.Unlock()

	loop := startReceiveLoop(tn)

	select {
	case <-tn.disconnected:
	case <-time.After(3 * time.Second):
		t.Fatal("receive loop did not disconnect on an idle link")
	}
	tn.Stop()
	loop.Wait()
}

// startReceiveLoop starts a receive loop as runSession does, with the session
// channel and a caller-owned wait group.
func startReceiveLoop(tn *Tunnel) *sync.WaitGroup {
	tn.mu.RLock()
	sessionDone := tn.disconnected
	tn.mu.RUnlock()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tn.receiveLoop(sessionDone)
	}()
	return &wg
}

func TestDialBudget(t *testing.T) {
	if got := dialBudget(0, 0); got != 2*time.Second {
		t.Errorf("first attempt = %v, want 2s", got)
	}
	if got := dialBudget(0, 3); got != 16*time.Second {
		t.Errorf("attempt 3 = %v, want 16s", got)
	}
	if got := dialBudget(0, 10); got != 16*time.Second {
		t.Errorf("attempt 10 = %v, want capped 16s", got)
	}
	if got := dialBudget(5*time.Second, 10); got != 5*time.Second {
		t.Errorf("configured timeout = %v, want verbatim 5s", got)
	}
}

// A network-change probe must kill an unresponsive session within
// netChangeProbeWindow measured FROM ARMING, and must never trip a session
// that was merely quiet before the probe or that answers it.
func TestNetworkChangeProbe(t *testing.T) {
	oldIdle, oldWindow := edgeIdleTimeout, netChangeProbeWindow
	edgeIdleTimeout = time.Hour // isolate the probe path
	netChangeProbeWindow = 700 * time.Millisecond
	defer func() { edgeIdleTimeout, netChangeProbeWindow = oldIdle, oldWindow }()

	var loops []*sync.WaitGroup
	runLoop := func(tn *Tunnel) net.Conn {
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		tn.mu.Lock()
		tn.raw = a
		tn.conn = proto.NewConn(a)
		tn.mu.Unlock()
		loops = append(loops, startReceiveLoop(tn))
		return b
	}

	// Unanswered probe: dead ~window after ARMING, not sooner, even though
	// the session was already quiet for longer than the window.
	tn := New(Options{Local: "localhost:0"})
	runLoop(tn)
	time.Sleep(time.Second) // quiet longer than the window
	tn.fastProbeAt.Store(time.Now().UnixNano())
	tn.interruptReader() // as OnNetworkChange does: arm, then wake the reader
	select {
	case <-tn.disconnected:
		t.Fatal("probe tripped on pre-arm silence")
	case <-time.After(200 * time.Millisecond):
	}
	select {
	case <-tn.disconnected:
	case <-time.After(5 * time.Second):
		t.Fatal("unanswered probe did not disconnect the session")
	}

	// Answered probe: an inbound frame after arming disarms it.
	tn2 := New(Options{Local: "localhost:0"})
	peer := runLoop(tn2)
	tn2.fastProbeAt.Store(time.Now().UnixNano())
	tn2.interruptReader()
	go func() { _ = proto.NewConn(peer).SendHeartbeatAck(1) }()
	disarmed := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if tn2.fastProbeAt.Load() == 0 {
			disarmed = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !disarmed {
		t.Fatal("answered probe was not disarmed")
	}
	select {
	case <-tn2.disconnected:
		t.Fatal("answered probe disconnected a healthy session")
	default:
	}

	// Stop both receive loops before the deferred timeout restore runs.
	tn.Stop()
	tn2.Stop()
	for _, loop := range loops {
		loop.Wait()
	}
}

// A network change while disconnected must cut the reconnect backoff short
// (the change may be the network coming back).
func TestNetworkChangeSkipsBackoff(t *testing.T) {
	tn := New(Options{Local: "localhost:0"})
	done := make(chan bool, 1)
	go func() { done <- tn.wait(context.Background(), time.Hour) }()
	time.Sleep(50 * time.Millisecond) // let wait park
	tn.OnNetworkChange()              // no live conn: nudges retryNow
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("wait returned false, want retry")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("network change did not cut the backoff wait short")
	}
}

// Wire values shown to the operator are stripped of terminal control
// characters.
func TestSanitizeDisplayStripsTerminalControl(t *testing.T) {
	cases := map[string]string{
		// The escape is removed and its text kept.
		"/orders\x1b]0;pwned\x07": "/orders]0;pwned",
		"GET\r\nX-Injected: 1":    "GETX-Injected: 1",
		"ops-laptop\x1b[8m":       "ops-laptop[8m",
		"plain/path?ok=1":         "plain/path?ok=1",
		"h\u00e9llo":              "h\u00e9llo",
		// Encoded C1, CSI as U+009B.
		"\u009b31mred": "31mred",
	}
	for in, want := range cases {
		if got := sanitizeDisplay(in); got != want {
			t.Errorf("sanitizeDisplay(%q) = %q, want %q", in, got, want)
		}
	}

	// No control characters remain for any input. A raw C1 byte is invalid
	// UTF-8 and is replaced.
	for _, in := range []string{"\x00\x1b\x7f\x9b", "a\x08b\x0cc", "\x1b_hidden\x9c"} {
		for _, r := range sanitizeDisplay(in) {
			if r == 0x7f || r < 0x20 || (r >= 0x80 && r <= 0x9f) {
				t.Fatalf("sanitizeDisplay(%q) kept %U", in, r)
			}
		}
	}
}

// ECONNRESET and EPIPE from a visitor hanging up are not reported.
func TestIgnoreClosedSwallowsOrdinaryDisconnects(t *testing.T) {
	ordinary := []error{
		nil,
		io.EOF,
		net.ErrClosed,
		http.ErrBodyReadAfterClose,
		syscall.ECONNRESET,
		syscall.EPIPE,
		fmt.Errorf("read tcp 10.0.0.1:443: %w", syscall.ECONNRESET),
		&net.OpError{Op: "write", Err: syscall.EPIPE},
		// A visitor closing the tab resets the mux stream.
		http2.StreamError{StreamID: 7, Code: http2.ErrCodeCancel},
		http2.StreamError{StreamID: 9, Code: http2.ErrCodeNo},
		http2.StreamError{StreamID: 11, Code: http2.ErrCodeStreamClosed},
		fmt.Errorf("copy: %w", http2.StreamError{StreamID: 13, Code: http2.ErrCodeCancel}),
	}
	for _, err := range ordinary {
		if got := ignoreClosed(err); got != nil {
			t.Errorf("ignoreClosed(%v) = %v, want nil", err, got)
		}
	}

	// Protocol errors are still reported.
	if got := ignoreClosed(http2.StreamError{StreamID: 3, Code: http2.ErrCodeProtocol}); got == nil {
		t.Error("a PROTOCOL_ERROR stream reset must be reported")
	}

	real := errors.New("connection reset by the local service")
	if got := ignoreClosed(real); got == nil {
		t.Fatal("a genuine failure must survive ignoreClosed")
	}
	if got := firstCopyError(nil, io.EOF, real); got != real {
		t.Fatalf("firstCopyError = %v, want the genuine failure", got)
	}
	if got := firstCopyError(io.EOF, syscall.ECONNRESET); got != nil {
		t.Fatalf("firstCopyError = %v, want nil when every copy ended normally", got)
	}
}

// The copy allocates nothing. The reader is reset outside the measured
// closure.
func TestCopyWithCountersTakesItsBufferFromThePool(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 256*1024)
	src := bytes.NewReader(nil)
	n := testing.AllocsPerRun(50, func() {
		src.Reset(payload)
		if err := copyWithCounters(io.Discard, src); err != nil {
			t.Fatal(err)
		}
	})
	if n != 0 {
		t.Fatalf("allocs per copy = %.1f, want 0: the buffer must come from copyBufPool", n)
	}
}

// At the limit, dial-back drops new connections without a reply.
func TestDispatchBoundsInFlightDataConnections(t *testing.T) {
	tn := New(Options{Local: "127.0.0.1:1"})

	// Fill every slot.
	for i := range maxConcurrentDataConns {
		select {
		case tn.dataSlots <- struct{}{}:
		default:
			t.Fatalf("slot %d refused, want %d available", i, maxConcurrentDataConns)
		}
	}

	var refused []error
	tn.opts.Handler = handlerFunc{onError: func(_ string, err error) { refused = append(refused, err) }}

	before := runtime.NumGoroutine()
	tn.dispatch(proto.MsgNewConnection, []byte(`{"connection_id":"conn_over","remote_addr":"203.0.113.9:1"}`))

	if len(refused) != 1 {
		t.Fatalf("got %d error events, want exactly 1 refusal", len(refused))
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Fatalf("goroutines %d -> %d: a refused connection must not spawn one", before, after)
	}

	// A freed slot admits the next connection.
	<-tn.dataSlots
	select {
	case tn.dataSlots <- struct{}{}:
	default:
		t.Fatal("a released slot was not reusable")
	}
}

// handlerFunc is a no-op EventHandler with one hook overridden.
type handlerFunc struct {
	onError func(label string, err error)
}

func (h handlerFunc) OnStateChange(string, State, State)                             {}
func (h handlerFunc) OnConnected(string, Info)                                       {}
func (h handlerFunc) OnDisconnected(string, error)                                   {}
func (h handlerFunc) OnError(label string, err error)                                { h.onError(label, err) }
func (h handlerFunc) OnDataConn(string, DataConnInfo)                                {}
func (h handlerFunc) OnHTTPRequest(string, RequestInfo)                              {}
func (h handlerFunc) OnRedirect(string, string, string)                              {}
func (h handlerFunc) OnPortsUpdate(string, []proto.DevicePort)                       {}
func (h handlerFunc) OnShutdownPolicy(string, string, string, proto.LimitType, bool) {}
func (h handlerFunc) OnDataClose(string, string, string, string, int64, int64, time.Duration, error) {
}

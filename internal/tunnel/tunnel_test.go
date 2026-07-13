package tunnel

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/localport/agent/internal/proto"
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

	tn.wg.Add(1)
	go tn.receiveLoop()

	select {
	case <-tn.disconnected:
	case <-time.After(3 * time.Second):
		t.Fatal("receive loop did not disconnect on an idle link")
	}
	tn.Stop()
	tn.wg.Wait()
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

	runLoop := func(tn *Tunnel) net.Conn {
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		tn.mu.Lock()
		tn.raw = a
		tn.conn = proto.NewConn(a)
		tn.mu.Unlock()
		tn.wg.Add(1)
		go tn.receiveLoop()
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
	tn.wg.Wait()
	tn2.wg.Wait()
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

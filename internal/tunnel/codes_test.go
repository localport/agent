package tunnel

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/ports"
	"github.com/localport/agent/internal/proto"
	"github.com/localport/agent/internal/transport"
)

// registerAnswers runs one connect attempt whose edges each read the
// Register and send the answer the hop's function returns, and returns the
// attempt's error.
func registerAnswers(t *testing.T, hops ...func(*fakeEdge)) error {
	t.Helper()
	tn, d := deviceTunnel(t, &fakeCredential{})
	result := make(chan error, 1)
	go func() { result <- tn.connect(context.Background(), 0) }()
	for _, hop := range hops {
		var edgeSide net.Conn
		select {
		case edgeSide = <-d.edges:
		case <-time.After(3 * time.Second):
			t.Fatal("connect did not dial")
		}
		t.Cleanup(func() { _ = edgeSide.Close() })
		edge := &fakeEdge{conn: proto.NewConn(edgeSide)}
		edge.expect(t, proto.MsgRegister)
		hop(edge)
	}
	select {
	case err := <-result:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("connect did not return")
		return nil
	}
}

func redirectTo(t *testing.T, addr string) func(*fakeEdge) {
	return func(e *fakeEdge) { e.send(t, proto.MsgRedirect, proto.RedirectPayload{EdgeAddr: addr}) }
}

// Register failures the user sees carry their code.
func TestRegisterFailuresAreCoded(t *testing.T) {
	trusted := redirectTo(t, "connect.eu.localport.dev:443")
	for name, tc := range map[string]struct {
		hops []func(*fakeEdge)
		want error
	}{
		"untrusted redirect": {[]func(*fakeEdge){redirectTo(t, "evil.example.com:443")}, ErrUntrustedRedirect},
		"too many redirects": {[]func(*fakeEdge){trusted, trusted, trusted, trusted, trusted}, ErrTooManyRedirects},
		"unexpected message": {[]func(*fakeEdge){func(e *fakeEdge) { e.send(t, proto.MsgHeartbeat, struct{}{}) }}, ErrRegisterFailed},
		"connection lost":    {[]func(*fakeEdge){func(e *fakeEdge) { _ = e.conn.Close() }}, ErrRegisterFailed},
	} {
		t.Run(name, func(t *testing.T) {
			if err := registerAnswers(t, tc.hops...); !errors.Is(err, tc.want) {
				t.Fatalf("connect = %v, want %v", err, tc.want)
			}
		})
	}
}

// The redirect target is edge text: it reaches --verbose and logs, not the
// user text.
func TestUntrustedRedirectHidesTheAddress(t *testing.T) {
	err := registerAnswers(t, redirectTo(t, "evil.example.com:443"))
	text, hidden := errcode.Render(err)
	if strings.Contains(text, "evil.example.com") || !hidden || !strings.Contains(err.Error(), "evil.example.com") {
		t.Fatalf("Render = %q, %v; Error() = %q; want the address in the cause only", text, hidden, err)
	}
}

// An edge error frame during registration shows the edge's message and code
// as received and stays retryable.
func TestRegisterEdgeErrorIsARetryableRemoteRefusal(t *testing.T) {
	err := registerAnswers(t, func(e *fakeEdge) {
		e.send(t, proto.MsgError, &proto.ErrorPayload{Code: "RS001", Message: "no port available"})
	})
	var regErr *RegistrationError
	if !errors.As(err, &regErr) || !regErr.Retryable {
		t.Fatalf("connect = %v, want a retryable RegistrationError", err)
	}
	if text, _ := errcode.Render(err); text != "no port available [RS001]" {
		t.Fatalf("Render = %q, want the edge message and code", text)
	}
}

// funcDialer dials with dial.
type funcDialer struct {
	dial func() (net.Conn, error)
}

func (d funcDialer) Kind() transport.Kind { return transport.KindRaw }
func (d funcDialer) Dial(context.Context, string, string) (net.Conn, error) {
	return d.dial()
}

// A data connection that cannot reach the edge, or whose ready message
// cannot be sent, reports AG076 to the live view.
func TestDataDialFailuresAreCoded(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	closedEdge := func() (net.Conn, error) {
		agentSide, edgeSide := net.Pipe()
		_ = edgeSide.Close()
		return agentSide, nil
	}
	for name, dialer := range map[string]transport.Dialer{
		"no control connection": nil,
		"edge dial fails":       funcDialer{func() (net.Conn, error) { return nil, errors.New("refused") }},
		"ready send fails":      funcDialer{closedEdge},
	} {
		t.Run(name, func(t *testing.T) {
			r := &recorder{}
			tn := New(Options{Local: ln.Addr().String(), Handler: r})
			tn.dialer = dialer
			tn.dataSlots <- struct{}{}
			tn.proxyData("c1", "203.0.113.9:1", connTarget{})
			r.mu.Lock()
			defer r.mu.Unlock()
			if len(r.errs) != 1 || !errors.Is(r.errs[0], ErrDataDialFailed) {
				t.Fatalf("OnDataClose errors %v, want one %v", r.errs, ErrDataDialFailed)
			}
		})
	}
}

// A device's port refusals and a failed local dial carry their codes.
func TestDialTargetFailuresAreCoded(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := uint16(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()
	tn := New(Options{Kind: proto.KindDevice, Host: "127.0.0.1", AllowPorts: ports.Ceiling{{From: closed, To: closed}}})
	tn.ports.Set(1, []proto.DevicePort{{Port: 22, Protocol: "tcp"}, {Port: closed, Protocol: "tcp"}})
	for name, tc := range map[string]struct {
		port   uint16
		want   error
		status int
	}{
		"no port":             {0, ErrPortRefused, http.StatusForbidden},
		"not listed":          {23, ErrPortRefused, http.StatusForbidden},
		"outside the ceiling": {22, ErrPortRefused, http.StatusForbidden},
		"nothing listening":   {closed, ErrLocalDialFailed, http.StatusBadGateway},
	} {
		if _, status, err := tn.dialTarget(tc.port); !errors.Is(err, tc.want) || status != tc.status {
			t.Errorf("%s: dialTarget(%d) = %d, %v; want %d, %v", name, tc.port, status, err, tc.status, tc.want)
		}
	}
}

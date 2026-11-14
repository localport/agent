package transport

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/localport/agent/internal/errcode"
)

type refusingDialer struct{ kind Kind }

func (d refusingDialer) Kind() Kind { return d.kind }

func (d refusingDialer) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 443}, Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
}

// A failed probe names the transports it tried; the dial errors, with their
// addresses, are the cause and reach the user only through --verbose.
func TestProbeFailureShowsNoDialAddress(t *testing.T) {
	_, _, err := Probe(context.Background(), "edge.example:443", time.Second,
		[]Dialer{refusingDialer{KindRaw}, refusingDialer{KindWS}}, nil)
	if !errors.Is(err, ErrNoTransport) {
		t.Fatalf("Probe = %v, want ErrNoTransport", err)
	}
	text, hidden := errcode.Render(err)
	if strings.Contains(text, "192.0.2.7") || !strings.Contains(text, "tried raw, ws") || !hidden {
		t.Fatalf("Render = %q, %v; want the kinds tried, no address, a hidden cause", text, hidden)
	}
	if !strings.Contains(err.Error(), "192.0.2.7") || !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("Error() = %q, want the dial errors as the cause", err)
	}
}

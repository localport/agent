// Package transport connects the agent to its edge server.
//
// Both carriers end on the edge HTTPS port, which routes them by SNI and ALPN.
//
//   - "raw" sends the wire protocol directly over TLS with the lowest
//     overhead.
//   - "ws" sends the same bytes in binary WebSocket frames, which pass DPI
//     and TLS-inspecting proxies.
//
// The data plane multiplexes over one HTTP/2 connection on the same carrier
// as the control connection. The edge identifies it by its first frame,
// MuxBind. See internal/tunnel/mux_session.go.
package transport

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

// ALPN identifiers must stay in sync with the edge's agent handler.
const (
	ALPNRaw = "localport-raw/1"
	ALPNWS  = "localport-ws/1"
)

// DefaultPort is used when an edge address omits an explicit port. The
// agent only ever speaks through the HTTPS-friendly port.
const DefaultPort = "443"

// DefaultWSPath is the HTTP path used for the WebSocket upgrade.
const DefaultWSPath = "/v1/control"

// Kind identifies one transport flavor.
type Kind string

const (
	KindRaw Kind = "raw"
	KindWS  Kind = "ws"
)

func (k Kind) String() string { return string(k) }

// Dialer opens a new edge connection. Implementations carry transport
// state (TLS config, WS path) but no per-call mutable state, so Dial is
// safe to call concurrently for data connections.
type Dialer interface {
	Kind() Kind
	Dial(ctx context.Context, host, port string) (net.Conn, error)
}

// ErrNoTransport is returned by Probe when every configured transport
// failed within the probe budget.
var ErrNoTransport = errors.New("no transport available: every candidate failed (check edge reachability and firewall)")

// SplitHostPort splits an edge address into host and port. When the port
// is missing, DefaultPort is used.
func SplitHostPort(addr string) (host, port string) {
	if h, p, err := net.SplitHostPort(addr); err == nil {
		return h, p
	}
	return strings.TrimSuffix(addr, ":"), DefaultPort
}

// Options configures the default dialers. It has no option to skip
// verification or override root CAs.
type Options struct {
	DialTimeout time.Duration
	WSPath      string

	// ServerName overrides the TLS SNI and verification name. A dial to a
	// per-edge host uses the zone connect host. Empty uses the dial host.
	ServerName string
}

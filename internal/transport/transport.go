// Package transport encapsulates how the agent reaches its edge server.
//
// Phase 1 supports two transports, both terminating on the edge HTTPS port
// and demultiplexed there by SNI + ALPN:
//
//   - "raw" — TLS-only. Wire protocol bytes ride directly inside the TLS
//     stream. Lowest overhead; works through dumb firewalls.
//   - "ws"  — TLS + WebSocket. Wire protocol bytes ride inside binary
//     WS frames. Survives DPI / HTTPS-inspecting MITM proxies.
//
// A future phase will add a multiplexing carrier and a per-network-
// fingerprint cache so the auto-detect decision survives reconnects.
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

// Options collects user-facing knobs for the default dialer set.
// Intentionally minimal — no insecure-skip-verify, no root-CA override.
type Options struct {
	DialTimeout time.Duration
	WSPath      string

	// ServerName sets the TLS SNI and verification name independently of
	// the dial host: dials to a per-edge hostname present the zone's
	// connect host instead. Empty derives the name from the dial host.
	ServerName string
}

package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// RawDialer establishes a TLS connection to the edge with ALPN
// localport-raw/1 and returns the TLS conn as-is, so wire protocol bytes write
// straight onto it. TLS 1.3 minimum, full server-cert verification, no insecure
// escape hatch.
type RawDialer struct {
	DialTimeout time.Duration
	ServerName  string // SNI override; empty = derive from dial host
}

func (d *RawDialer) Kind() Kind { return KindRaw }

func (d *RawDialer) Dial(ctx context.Context, host, port string) (net.Conn, error) {
	timeout := d.DialTimeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tcp, err := (&net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}

	conn := tls.Client(tcp, agentTLSConfig(d.ServerName, host, ALPNRaw))
	if err := conn.HandshakeContext(ctx); err != nil {
		tcp.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	if got := conn.ConnectionState().NegotiatedProtocol; got != ALPNRaw {
		conn.Close()
		return nil, fmt.Errorf("alpn mismatch: edge negotiated %q, expected %q", got, ALPNRaw)
	}
	return conn, nil
}

// sessionCache lets a reconnect, a redirect and the mux dial resume the TLS
// session established by an earlier connection to the same edge, turning a full
// handshake into a PSK exchange: one round trip instead of two, and no signature
// for either side to compute.
//
// It is process-wide because that is the only way the second connection to an
// edge can reuse the first one's session. crypto/tls keys entries by server
// name, so sessions never cross edges.
//
// This does not enable 0-RTT. Go only offers early data over QUIC; on a TCP
// connection the server rejects it outright, which is the behaviour we want:
// early data is replayable, and a replayed request would be delivered to the
// customer's service a second time.
var sessionCache = tls.NewLRUClientSessionCache(64)

// agentTLSConfig keeps the TLS posture identical across transports. SNI
// is serverName when set (the caller derives the zone connect host for
// redirect targets), else derived from host. Literal IPs leave SNI empty
// (crypto/tls refuses IP-literal SNI).
func agentTLSConfig(serverName, host, alpn string) *tls.Config {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{alpn},
		ClientSessionCache: sessionCache,
	}
	name := serverName
	if name == "" {
		name = host
	}
	if _, err := netip.ParseAddr(name); err != nil {
		cfg.ServerName = name
	}
	return cfg
}

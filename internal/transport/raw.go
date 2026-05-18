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
// localport-raw/1 and returns the TLS conn as-is — wire protocol bytes
// write straight onto it. TLS 1.3 minimum, full server-cert verification,
// no insecure escape hatch.
type RawDialer struct {
	DialTimeout time.Duration
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

	conn := tls.Client(tcp, agentTLSConfig(host, ALPNRaw))
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

// agentTLSConfig keeps the TLS posture identical across transports. SNI
// is derived from host unless host is a literal IP, in which case it
// stays empty (crypto/tls refuses IP-literal SNI).
func agentTLSConfig(host, alpn string) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{alpn},
	}
	if _, err := netip.ParseAddr(host); err != nil {
		cfg.ServerName = host
	}
	return cfg
}

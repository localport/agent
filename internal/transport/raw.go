package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
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

// sessionCache lets reconnects, redirects and mux dials resume an earlier TLS
// session with the same edge. Resumption uses PSK, saving a round trip and the
// signatures. The cache is process-wide and keyed by server name. Go does not
// offer 0-RTT over TCP, so no request can be replayed.
var sessionCache = tls.NewLRUClientSessionCache(64)

// agentTLSConfig returns the TLS config shared by all transports. ServerName is
// serverName when set, otherwise the dial host.
//
// An IP literal is kept as ServerName so hostname verification stays on.
// crypto/tls omits SNI for an IP (RFC 6066) and verifies the IP SANs.
func agentTLSConfig(serverName, host, alpn string) *tls.Config {
	name := serverName
	if name == "" {
		name = host
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{alpn},
		ClientSessionCache: sessionCache,
		ServerName:         name,
	}
}

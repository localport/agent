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
	ClientCert  ClientCert
}

func (d *RawDialer) Kind() Kind { return KindRaw }

func (d *RawDialer) Dial(ctx context.Context, host, port string) (net.Conn, error) {
	timeout := d.DialTimeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tcp, err := dialEdge(ctx, &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}, host, port)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}

	conn := tls.Client(tcp, agentTLSConfig(d.ServerName, host, ALPNRaw, d.ClientCert))
	if err := conn.HandshakeContext(ctx); err != nil {
		tcp.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	if got := conn.ConnectionState().NegotiatedProtocol; got != ALPNRaw {
		conn.Close()
		return nil, fmt.Errorf("alpn mismatch: edge negotiated %q, expected %q", got, ALPNRaw)
	}
	lastGood.remember(host, tcp.RemoteAddr())
	return conn, nil
}

// sessionCache lets reconnects, redirects and mux dials resume an earlier TLS
// session with the same edge. Resumption uses PSK, saving a round trip and the
// signatures. The cache is process-wide and keyed by server name, and serves
// only dials without a client certificate. Go does not offer 0-RTT over TCP,
// so no request can be replayed.
var sessionCache = tls.NewLRUClientSessionCache(64)

// agentTLSConfig returns the TLS config shared by all transports. ServerName is
// serverName when set, otherwise the dial host.
//
// An IP literal is kept as ServerName so hostname verification stays on.
// crypto/tls omits SNI for an IP (RFC 6066) and verifies the IP SANs.
//
// With a client certificate the config presents it whenever the edge asks and
// resumes only from client.SessionCache: the edge restores a resumed session's
// client certificate from the handshake that created it, so a session made
// with one certificate must never be resumed by a dial presenting another.
func agentTLSConfig(serverName, host, alpn string, client ClientCert) *tls.Config {
	name := serverName
	if name == "" {
		name = host
	}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{alpn},
		ClientSessionCache: sessionCache,
		ServerName:         name,
	}
	if client.Certificate != nil {
		cert := client.Certificate
		cfg.ClientSessionCache = client.SessionCache
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert, nil }
	}
	return cfg
}

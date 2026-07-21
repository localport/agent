package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// tlsEchoServer serves TLS with the given ALPN and reports each connection's
// resumption state.
func tlsEchoServer(t *testing.T, alpn string) (addr string, resumed chan bool, roots *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "edge.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"edge.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{alpn},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	states := make(chan bool, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tc := c.(*tls.Conn)
				if err := tc.Handshake(); err != nil {
					return
				}
				states <- tc.ConnectionState().DidResume
				// Hold briefly so the client observes its own state before close.
				time.Sleep(50 * time.Millisecond)
			}(c)
		}
	}()

	return ln.Addr().String(), states, pool
}

// A second connection to the same edge must resume the first one's session.
// This is what turns a reconnect, a redirect and the mux dial into a one
// round-trip handshake with no signature to compute on either side.
func TestTLSSessionIsResumedOnReconnect(t *testing.T) {
	addr, serverResumed, roots := tlsEchoServer(t, ALPNRaw)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	dial := func() *tls.Conn {
		t.Helper()
		tcp, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		cfg := agentTLSConfig("edge.test", host, ALPNRaw)
		cfg.RootCAs = roots
		conn := tls.Client(tcp, cfg)
		if err := conn.Handshake(); err != nil {
			t.Fatalf("handshake: %v", err)
		}
		return conn
	}

	first := dial()
	if first.ConnectionState().DidResume {
		t.Fatal("the first connection cannot resume anything")
	}
	if got := <-serverResumed; got {
		t.Fatal("server reported the first connection as resumed")
	}
	// The ticket arrives after the handshake completes, so give the client a
	// moment to file it before dialing again.
	first.Read(make([]byte, 1))
	first.Close()

	second := dial()
	defer second.Close()

	if !second.ConnectionState().DidResume {
		t.Error("second connection did not resume: every reconnect pays a full handshake")
	}
	if got := <-serverResumed; !got {
		t.Error("server did not see the second connection as resumed")
	}
}

// Sessions are keyed by server name, so a different edge never reuses another's
// ticket even though the cache is process-wide.
func TestTLSSessionsDoNotCrossServerNames(t *testing.T) {
	addr, _, roots := tlsEchoServer(t, ALPNRaw)
	host, port, _ := net.SplitHostPort(addr)

	dialAs := func(serverName string) *tls.Conn {
		t.Helper()
		tcp, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		cfg := agentTLSConfig(serverName, host, ALPNRaw)
		cfg.RootCAs = roots
		cfg.InsecureSkipVerify = true // the cert only names edge.test
		conn := tls.Client(tcp, cfg)
		if err := conn.Handshake(); err != nil {
			t.Fatalf("handshake as %s: %v", serverName, err)
		}
		return conn
	}

	first := dialAs("edge-one.test")
	first.Read(make([]byte, 1))
	first.Close()

	second := dialAs("edge-two.test")
	defer second.Close()

	if second.ConnectionState().DidResume {
		t.Error("a session was reused across server names")
	}
}

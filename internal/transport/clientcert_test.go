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

// handshakeSeen is what the server observed on one connection.
type handshakeSeen struct {
	resumed bool
	client  string // CommonName of the client certificate, empty for none
}

// clientCertServer is a TLS server that asks for a client certificate without
// verifying it, as the edge does, and reports what each handshake presented.
func clientCertServer(t *testing.T) (addr string, seen chan handshakeSeen, roots *x509.CertPool) {
	t.Helper()
	server := selfSigned(t, "edge.test")
	roots = x509.NewCertPool()
	roots.AddCert(server.Leaf)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*server},
		NextProtos:   []string{ALPNRaw},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequestClientCert,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	seen = make(chan handshakeSeen, 8)
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
				st := tc.ConnectionState()
				got := handshakeSeen{resumed: st.DidResume}
				if len(st.PeerCertificates) > 0 {
					got.client = st.PeerCertificates[0].Subject.CommonName
				}
				seen <- got
				// Writing flushes the session ticket before the close.
				_, _ = tc.Write([]byte{0})
				time.Sleep(50 * time.Millisecond)
			}(c)
		}
	}()
	return ln.Addr().String(), seen, roots
}

func selfSigned(t *testing.T, cn string) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{cn},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// A device presents its certificate, a reconnect resumes with the same one,
// and a dial presenting a renewed certificate from its own cache performs a
// full handshake that sends the renewed certificate. A dial without a
// certificate never resumes a device's session.
func TestClientCertificateIsPresentedAndNeverResumedAcrossCertificates(t *testing.T) {
	addr, seen, roots := clientCertServer(t)
	host, port, _ := net.SplitHostPort(addr)

	dial := func(client ClientCert) {
		t.Helper()
		tcp, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		cfg := agentTLSConfig("edge.test", host, ALPNRaw, client)
		cfg.RootCAs = roots
		conn := tls.Client(tcp, cfg)
		if err := conn.Handshake(); err != nil {
			t.Fatalf("handshake: %v", err)
		}
		// Reading the server's byte makes crypto/tls cache the session ticket.
		_, _ = conn.Read(make([]byte, 1))
		conn.Close()
	}
	expect := func(step string, want handshakeSeen) {
		t.Helper()
		if got := <-seen; got != want {
			t.Fatalf("%s: server saw %+v, want %+v", step, got, want)
		}
	}

	current := ClientCert{Certificate: selfSigned(t, "current"), SessionCache: tls.NewLRUClientSessionCache(4)}
	renewed := ClientCert{Certificate: selfSigned(t, "renewed"), SessionCache: tls.NewLRUClientSessionCache(4)}

	dial(current)
	expect("first dial", handshakeSeen{resumed: false, client: "current"})
	dial(current)
	expect("reconnect", handshakeSeen{resumed: true, client: "current"})
	dial(renewed)
	expect("renewed certificate", handshakeSeen{resumed: false, client: "renewed"})
	dial(ClientCert{})
	expect("no certificate", handshakeSeen{resumed: false, client: ""})
}

package connect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// A refused client certificate must reach the person who ran the command.
// Under TLS 1.3 it arrives on the first read, not from tls.Dial.
func TestRefusedClientCertificateIsReported(t *testing.T) {
	srvCert, pool := selfSignedServer(t)

	// Requires a client certificate and trusts NOBODY, so every client is
	// refused the same way the edge refuses an unscoped identity.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    x509.NewCertPool(),
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			// Force the handshake so the alert is sent, then drop it.
			go func() {
				_ = c.(*tls.Conn).HandshakeContext(context.Background())
				c.Close()
			}()
		}
	}()

	var (
		mu     sync.Mutex
		errs   []error
		conned bool
	)
	p := &Proxy{
		Remote:    ln.Addr().String(),
		LocalAddr: "127.0.0.1:0",
		TLSConfig: &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13},
		OnConn:    func(string, string) { mu.Lock(); conned = true; mu.Unlock() },
		OnError:   func(e error) { mu.Lock(); errs = append(errs, e); mu.Unlock() },
	}

	// Run the proxy on a listener we control so the test can dial it.
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen local: %v", err)
	}
	localAddr := local.Addr().String()
	local.Close()
	p.LocalAddr = localAddr

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Run(ctx) }()

	// Give the proxy a moment to bind.
	var conn net.Conn
	for i := 0; i < 50; i++ {
		if conn, err = net.Dial("tcp", localAddr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if conn == nil {
		t.Fatalf("proxy never accepted: %v", err)
	}
	// Write something so the copy actually reads from the remote side.
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	_, _ = io.ReadAll(conn)
	conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(errs)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(errs) == 0 {
		t.Fatal("a refused client certificate produced NO error; the failure is invisible to the operator")
	}
	if !conned {
		t.Log("note: OnConn did not fire, so the rejection arrived during the dial")
	}
	got := errs[0].Error()
	if !strings.Contains(got, "refused the certificate") && !strings.Contains(got, "dial ") {
		t.Fatalf("error is not actionable: %s", got)
	}
}

// The message must name what the holder can check.
func TestFriendlyStreamErrorNamesTheNextStep(t *testing.T) {
	err := friendlyStreamError("gw-01.eu.localport.dev:443",
		errors.New("remote error: tls: bad certificate"))
	msg := err.Error()
	for _, want := range []string{"refused the certificate", "access to the device", "revoked", "localport identity list"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message does not mention %q:\n%s", want, msg)
		}
	}
	// The cause survives for anything unwrapping it.
	if !strings.Contains(msg, "bad certificate") {
		t.Fatal("the underlying TLS alert must be preserved")
	}
}

func TestNormalCloseIsNotReported(t *testing.T) {
	for _, err := range []error{nil, io.EOF, net.ErrClosed} {
		if !isNormalClose(err) {
			t.Fatalf("%v should be an ordinary close, not a reported failure", err)
		}
	}
	if isNormalClose(errors.New("remote error: tls: bad certificate")) {
		t.Fatal("a TLS alert must NOT be treated as an ordinary close")
	}
}

func selfSignedServer(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

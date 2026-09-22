package access

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestBuildTLSConfigBundle(t *testing.T) {
	dir := t.TempDir()
	pemFile := writePEMBundle(t, dir, "client.pem")

	cfg, err := BuildTLSConfig(pemFile, "", "", "db-acme.eu.localport.dev:5432", "")
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if cfg.ServerName != "db-acme.eu.localport.dev" {
		t.Fatalf("ServerName = %q", cfg.ServerName)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates = %d", len(cfg.Certificates))
	}
	// RootCAs is nil so the server is verified against the system trust store.
	// The edge presents a publicly trusted region wildcard that the tunnel CA
	// does not sign. The PEM chain is only presented to the server.
	if cfg.RootCAs != nil {
		t.Fatal("RootCAs must stay nil: the server is verified against system roots, not against the credential's own CA")
	}
	// TLS 1.3 encrypts the client Certificate message. Under 1.2 the SPIFFE
	// identity is sent in cleartext.
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %#x, want TLS 1.3", cfg.MinVersion)
	}
}

func TestBuildTLSConfigRejectsAmbiguousMode(t *testing.T) {
	if _, err := BuildTLSConfig("a", "b", "", "host:1", ""); err == nil {
		t.Fatal("expected error when both --pem and --p12 are set")
	}
	if _, err := BuildTLSConfig("", "", "", "host:1", ""); err == nil {
		t.Fatal("expected error when neither --pem nor --p12 is set")
	}
}

// An IP remote keeps the literal as its ServerName. crypto/tls refuses an
// empty ServerName, omits SNI for an IP (RFC 6066) and verifies the IP SANs.
func TestResolveServerName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"db-acme.eu.localport.dev:5432", "db-acme.eu.localport.dev"},
		{"127.0.0.1:5432", "127.0.0.1"},
		{"[::1]:5432", "::1"},
		{"203.0.113.5:443", "203.0.113.5"},
		{"host", "host"},
	}
	for _, tc := range cases {
		if got := resolveServerName(tc.in, ""); got != tc.want {
			t.Errorf("resolveServerName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if resolveServerName("anything:1", "override") != "override" {
		t.Errorf("override should win")
	}
}

// The PEM file holds a private key, so any group or other permission bit is
// refused. Browsers save downloads as 0644, which the setup docs fix with
// `chmod 600`.
func TestBuildTLSConfigRejectsLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits not enforced on Windows")
	}
	dir := t.TempDir()
	pemFile := writePEMBundle(t, dir, "client.pem")
	if err := os.Chmod(pemFile, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := BuildTLSConfig(pemFile, "", "", "host:1", ""); err == nil {
		t.Fatal("expected loose-permission rejection")
	}
}

// A .p12 file must be owner-only, as for PEM, since archive passwords are often
// weak or shared.
func TestPKCS12IsReadThroughThePrivateFilePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits not enforced on Windows")
	}
	dir := t.TempDir()
	archive := writePKCS12(t, dir, "client.p12", "hunter2")

	if _, err := BuildTLSConfig("", archive, "hunter2", "host:1", ""); err != nil {
		t.Fatalf("a 0600 archive must load: %v", err)
	}

	if err := os.Chmod(archive, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := BuildTLSConfig("", archive, "hunter2", "host:1", ""); err == nil {
		t.Fatal("a world-readable .p12 must be refused, exactly like a loose PEM file")
	}
}

// Server verification stays on for every remote, loopback included.
func TestBaseTLSConfigAlwaysVerifiesTheServer(t *testing.T) {
	remotes := []string{
		"db-acme.eu.localport.dev:5432",
		"127.0.0.1:8080",
		"[::1]:8080",
		"localhost:8080",
		"anything.localhost:8080",
	}
	for _, remote := range remotes {
		cfg := BaseTLSConfig(remote, "")
		if cfg.InsecureSkipVerify {
			t.Errorf("BaseTLSConfig(%q) skips server verification", remote)
		}
		if cfg.RootCAs != nil {
			t.Errorf("BaseTLSConfig(%q) pins RootCAs instead of using system roots", remote)
		}
	}
}

// --pem pointing at the identity store's cert.pem gets a specific error in
// place of the crypto/tls PEM block type message.
func TestPEMBundleWithoutAKeyNamesTheMistake(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")

	_, caDER := testCA(t, 1)
	var buf bytes.Buffer
	_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := loadPEM(path)
	if err == nil {
		t.Fatal("a PEM file with no private key must be refused")
	}
	if !strings.Contains(err.Error(), "--pem") {
		t.Fatalf("the error must name the mistake and the way out, got: %v", err)
	}
}

// A CA with the same serial as the leaf still counts as a chain certificate.
// Serials are unique only within their CA (RFC 5280 4.1.2.2).
func TestPEMBundleWithCASharingTheLeafSerialIsAccepted(t *testing.T) {
	const shared = 4242
	dir := t.TempDir()
	pemFile := writePEMBundleWithSerials(t, dir, "client.pem", shared, shared)

	cert, err := loadPEM(pemFile)
	if err != nil {
		t.Fatalf("a PEM file whose CA shares the leaf's serial must load: %v", err)
	}
	// Leaf is set so crypto/tls does not parse it on each handshake.
	if cert.Leaf == nil {
		t.Fatal("Leaf must be set on the loaded certificate")
	}
	if cert.Leaf.SerialNumber.Int64() != shared {
		t.Fatalf("Leaf serial = %s, want %d", cert.Leaf.SerialNumber, shared)
	}
}

func TestPEMBundleWithoutACARefuses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.pem")

	caKey, caDER := testCA(t, 1)
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	leafDER, leafKeyDER := testLeaf(t, caCert, caKey, 2)

	var buf bytes.Buffer
	_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	_ = pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER})
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := loadPEM(path); err == nil {
		t.Fatal("a PEM file with no chain to present must be refused here, not at the far side's handshake")
	}
}

// writePEMBundle creates a self-signed CA, signs a leaf with it, and
// writes [leaf, key, ca] into a single PEM file with 0600 perms.
// ---------------------------------------------------------------------------

func testCA(t *testing.T, serial int64) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	return key, der
}

func testLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, serial int64) (certDER, keyDER []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err = x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	keyDER, err = x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return certDER, keyDER
}

// writePEMBundle creates a self-signed CA, signs a leaf with it, and writes
// [leaf, key, ca] into a single PEM file with 0600 perms.
func writePEMBundle(t *testing.T, dir, name string) string {
	t.Helper()
	return writePEMBundleWithSerials(t, dir, name, 1, 2)
}

// writePEMBundleWithSerials is writePEMBundle with the serials chosen, so a CA
// and a leaf can deliberately share one.
func writePEMBundleWithSerials(t *testing.T, dir, name string, caSerial, leafSerial int64) string {
	t.Helper()

	caKey, caDER := testCA(t, caSerial)
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	leafDER, leafKeyDER := testLeaf(t, caCert, caKey, leafSerial)

	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	_ = pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER})
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return path
}

// writePKCS12 writes a password-protected archive holding leaf, key and chain,
// at 0600.
func writePKCS12(t *testing.T, dir, name, password string) string {
	t.Helper()

	caKey, caDER := testCA(t, 1)
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	leafDER, leafKeyDER := testLeaf(t, caCert, caKey, 2)
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	leafKey, err := x509.ParseECPrivateKey(leafKeyDER)
	if err != nil {
		t.Fatalf("parse leaf key: %v", err)
	}

	raw, err := pkcs12.Modern.Encode(leafKey, leafCert, []*x509.Certificate{caCert}, password)
	if err != nil {
		t.Fatalf("encode pkcs12: %v", err)
	}

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// A certificate whose validity starts in the future is refused with the local
// clock in the message, since a wrong clock is the usual cause.
func TestAssertLeafFreshRefusesANotYetValidCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "gw-01"},
		NotBefore:    time.Now().Add(time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	err = assertLeafFresh(tls.Certificate{Certificate: [][]byte{der}})
	if err == nil || !strings.Contains(err.Error(), "clock reads") {
		t.Fatalf("want a not-yet-valid refusal naming the clock, got %v", err)
	}
}

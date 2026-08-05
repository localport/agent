package connect

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestBuildTLSConfigBundle(t *testing.T) {
	dir := t.TempDir()
	bundle := writePEMBundle(t, dir, "client.pem")

	cfg, err := BuildTLSConfig(bundle, "", "", "db.tunnel.localport.dev:5432", "")
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if cfg.ServerName != "db.tunnel.localport.dev" {
		t.Fatalf("ServerName = %q", cfg.ServerName)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates = %d", len(cfg.Certificates))
	}
	// RootCAs stays NIL: the SERVER is verified against the system trust store.
	//
	// The edge presents the region zone wildcard, publicly trusted and issued by
	// Let's Encrypt, as its mTLS server identity. It is not signed by the tunnel
	// CA and never could be for a customer-registered CA, since we hold no key to
	// sign one with. Pinning the bundle's CA here would reject every connection
	// with "certificate signed by unknown authority". The bundle's chain is used
	// in the other direction only: it is what we PRESENT.
	if cfg.RootCAs != nil {
		t.Fatal("RootCAs must stay nil: the server is verified against system roots, not against the credential's own CA")
	}
	if cfg.MinVersion != 0x0303 { // tls.VersionTLS12
		t.Fatalf("MinVersion = %#x, want TLS 1.2", cfg.MinVersion)
	}
}

func TestBuildTLSConfigRejectsAmbiguousMode(t *testing.T) {
	if _, err := BuildTLSConfig("a", "b", "", "host:1", ""); err == nil {
		t.Fatal("expected error when both bundle and p12 are set")
	}
	if _, err := BuildTLSConfig("", "", "", "host:1", ""); err == nil {
		t.Fatal("expected error when neither bundle nor p12 is set")
	}
}

// An IP remote keeps the literal as its ServerName.
//
// Returning "" made crypto/tls refuse to handshake at all, with "either
// ServerName or InsecureSkipVerify must be specified", so
// `--remote 203.0.113.5:443` failed with a message naming neither the address
// nor the certificate. The literal is also the CORRECT value: crypto/tls omits
// SNI for an IP (RFC 6066 forbids it there) and VerifyHostname then matches the
// IP SANs, which is the check that should run.
func TestResolveServerName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"db.tunnel.localport.dev:5432", "db.tunnel.localport.dev"},
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

// The credential file carries a private key, so it is read through the
// owner-only path: `perm&0o077 != 0` is refused. Browsers write downloads 0644,
// hence the `chmod 600` in the setup instructions.
func TestBuildTLSConfigRejectsLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits not enforced on Windows")
	}
	dir := t.TempDir()
	bundle := writePEMBundle(t, dir, "client.pem")
	if err := os.Chmod(bundle, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := BuildTLSConfig(bundle, "", "", "host:1", ""); err == nil {
		t.Fatal("expected loose-permission rejection")
	}
}

// A .p12 goes through the same owner-only path as the PEM bundle. A password on
// an exported archive is not a reason to relax that: they are routinely weak or
// shared.
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
		t.Fatal("a world-readable .p12 must be refused, exactly like a loose PEM bundle")
	}
}

// No remote turns server verification off, loopback included. This is the
// connection that presents a client certificate, and agent/ is public.
func TestBaseTLSConfigAlwaysVerifiesTheServer(t *testing.T) {
	remotes := []string{
		"db.tunnel.localport.dev:5432",
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

// A CA sharing the leaf's serial must not make the bundle look CA-less.
//
// The chain was counted by "every certificate whose serial differs from the
// leaf's", but a serial is unique only within the CA that assigned it
// (RFC 5280 4.1.2.2). Two independent PKIs both numbering from 1 is ordinary,
// so a legitimate CA was skipped and the bundle refused for carrying none.
func TestPEMBundleWithCASharingTheLeafSerialIsAccepted(t *testing.T) {
	const shared = 4242
	dir := t.TempDir()
	bundle := writePEMBundleWithSerials(t, dir, "client.pem", shared, shared)

	cert, err := loadFromPEMBundle(bundle)
	if err != nil {
		t.Fatalf("a bundle whose CA shares the leaf's serial must load: %v", err)
	}
	// Parsed once and kept, so crypto/tls does not re-parse the leaf on every
	// handshake.
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

	if _, err := loadFromPEMBundle(path); err == nil {
		t.Fatal("a bundle with no chain to present must be refused here, not at the far side's handshake")
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

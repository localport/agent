package connect

import (
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
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs nil")
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

func TestResolveServerName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"db.tunnel.localport.dev:5432", "db.tunnel.localport.dev"},
		{"127.0.0.1:5432", ""},
		{"[::1]:5432", ""},
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

	caKey, caDER := testCA(t, 1)
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	leafDER, leafKeyDER := testLeaf(t, caCert, caKey, 2)

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

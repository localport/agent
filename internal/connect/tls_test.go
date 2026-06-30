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

// writePEMBundle creates a self-signed CA, signs a leaf with it, and
// writes [leaf, key, ca] into a single PEM file with 0600 perms.
func writePEMBundle(t *testing.T, dir, name string) string {
	t.Helper()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca: %v", err)
	}

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	_ = pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return path
}

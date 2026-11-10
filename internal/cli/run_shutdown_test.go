package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/identity"
)

// closedAddr is a local address nothing listens on.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// storeDevice writes a device credential for ref into store as enrolment
// leaves it: key, certificate and meta.json, private to the owner.
func storeDevice(t *testing.T, store *identity.Store, ref identity.Ref, apiURL string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spiffe, _ := url.Parse("spiffe://" + ref.Team + ".mtls.localport.dev/device/" + ref.Identity)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: ref.Identity},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), URIs: []*url.URL{spiffe},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := json.Marshal(identity.Meta{
		Identity: ref.Identity, Team: ref.Team, Kind: identity.KindDevice, SpiffeID: spiffe.String(),
		Key: identity.KeyRef{Backing: identity.BackingFile, File: "key.pem"}, Cert: "cert.pem",
		Source: identity.SourceToken, APIURL: apiURL, Serial: "07", NotAfter: tmpl.NotAfter, UpdatedAt: time.Now(),
		Device: &identity.DeviceInfo{Host: "gw-01.example.test", Region: "eu"},
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := store.Dir(ref)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"key.pem":   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		"cert.pem":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"meta.json": meta,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// A served device with the recording uploader running stops when its parent
// context ends: every loop that outlives the devices is stopped before it is
// waited for.
func TestServeDevicesReturnsWhenItsParentEnds(t *testing.T) {
	edge := closedAddr(t)
	prev := resolveEdge
	resolveEdge = func(string) string { return edge }
	t.Cleanup(func() { resolveEdge = prev })

	base := t.TempDir()
	store := &identity.Store{Root: filepath.Join(base, "identity"), Base: base, BaseChosen: true}
	ref := identity.Ref{Team: "01kpq7x2abcd34", Kind: identity.KindDevice, Identity: "tun12345.gw-01"}
	storeDevice(t, store, ref, "http://"+closedAddr(t))

	running := make(chan struct{})
	devicesRunning = func() { close(running) }
	t.Cleanup(func() { devicesRunning = nil })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serveDevices(ctx, "test", store, []config.LocalDevice{{Identity: ref}}, true, false, nil)
	}()
	select {
	case <-running:
	case err := <-done:
		t.Fatalf("serveDevices returned %v before its devices ran", err)
	case <-time.After(15 * time.Second):
		t.Fatal("the devices did not start within 15 s")
	}
	cancel()
	select {
	case err := <-done:
		if errors.Is(err, errNoDeviceStarts) {
			t.Fatal("no device started, so nothing was served or stopped")
		}
		t.Logf("serveDevices returned %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("serveDevices did not return within 15 s of its parent ending")
	}
}

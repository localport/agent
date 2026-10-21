package identity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/localport/agent/internal/security"
)

const deviceURI = "spiffe://01kpq7x2abcd34.mtls.localport.dev/device/tun12345/gw-01"

var deviceRef = Ref{Team: "01kpq7x2abcd34", Kind: KindDevice, Identity: "tun12345.gw-01"}

// testCA signs CSRs the way the control plane does, with a SPIFFE URI SAN.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	// uri is the SPIFFE ID it issues. wrongKey makes signCSR certify a key
	// other than the requested one.
	uri      string
	wrongKey bool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test ca"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, uri: deviceURI}
}

// sign issues a leaf for pub valid over [notBefore, notAfter].
func (ca *testCA) sign(t *testing.T, pub crypto.PublicKey, notBefore, notAfter time.Time) []byte {
	t.Helper()
	u, err := url.Parse(ca.uri)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		URIs:         []*url.URL{u},
	}, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func (ca *testCA) signCSR(t *testing.T, csrPEM string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatal("request carries no CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature: %v", err)
	}
	if pub, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("CSR key is %T, the device route accepts P-256 only", csr.PublicKey)
	}
	if ca.wrongKey {
		return ca.sign(t, &testKey(t).PublicKey, notBefore, notAfter)
	}
	return ca.sign(t, csr.PublicKey, notBefore, notAfter)
}

var testKeys = DeviceKeys{
	TicketKeys: []TicketKey{testTicketKey("k1", 1)},
}

// testTicketKey is a valid ticket key whose Ed25519 seed is 32 copies of seed.
func testTicketKey(kid string, seed byte) TicketKey {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	return TicketKey{KID: kid, PublicKey: base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))}
}

func TestEnrolDeviceRoundTrip(t *testing.T) {
	ca := newTestCA(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/devices/enrol" {
			t.Errorf("request %s %s, want POST /v1/devices/enrol", r.Method, r.URL.Path)
		}
		var body struct {
			JoinToken string `json:"join_token"`
			CSRPEM    string `json:"csr_pem"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.JoinToken != "lpj_secret" {
			t.Errorf("join_token = %q", body.JoinToken)
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("the join token travels in the body only")
		}
		writeJSON(t, w, map[string]any{
			"cert_pem":          string(ca.signCSR(t, body.CSRPEM, time.Now().Add(-time.Minute), time.Now().Add(30*24*time.Hour))),
			"ca_chain_pem":      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})),
			"team_id":           "01kpq7x2abcd34",
			"tunnel_identifier": "tun12345",
			"prefix":            "gw-01",
			"device_host":       "gw-01.factory.eu.localport.dev",
			"region":            "eu",
			"renew_after":       time.Now().Add(20 * 24 * time.Hour).UTC().Format(time.RFC3339),
			"keys":              testKeys,
		})
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}

	m, err := client.EnrolDevice(context.Background(), " lpj_secret\n", 0, nil)
	if err != nil {
		t.Fatalf("EnrolDevice: %v", err)
	}
	store := &Store{Root: t.TempDir()}
	ref, err := store.Save(context.Background(), *m)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if ref != deviceRef {
		t.Fatalf("ref = %+v, want %+v", ref, deviceRef)
	}
	if got := filepath.Base(store.Dir(ref)); got != "device-tun12345.gw-01" {
		t.Fatalf("credential directory = %q", got)
	}

	loaded, err := store.Load(ref)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	d := loaded.Meta.Device
	if d == nil || d.Host != "gw-01.factory.eu.localport.dev" || d.Region != "eu" {
		t.Fatalf("device details = %+v", d)
	}
	// Save stores the certificate only; the enrolled keys are the caller's to
	// pass to TicketKeys, and never land in meta.json.
	if m.DeviceKeys == nil || !slices.Equal(m.DeviceKeys.TicketKeys, testKeys.TicketKeys) {
		t.Fatalf("enrolment keys = %+v", m.DeviceKeys)
	}
	if _, renews := loaded.Meta.NextRenewal(); !renews {
		t.Fatal("a device credential must renew")
	}
	if _, err := loaded.TLSCertificate(); err != nil {
		t.Fatalf("stored credential is unusable: %v", err)
	}
}

// The certificate is authoritative: a response describing another device comes
// from a broken control plane and is stored under neither name.
func TestEnrolDeviceRefusesAResponseThatDisagreesWithItsCertificate(t *testing.T) {
	ca := newTestCA(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			CSRPEM string `json:"csr_pem"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		writeJSON(t, w, map[string]any{
			"cert_pem":          string(ca.signCSR(t, body.CSRPEM, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))),
			"team_id":           "01kpq7x2abcd34",
			"tunnel_identifier": "tun12345",
			"prefix":            "other",
			"device_host":       "other.factory.eu.localport.dev",
		})
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	if _, err := client.EnrolDevice(context.Background(), "lpj_x", 0, nil); err == nil {
		t.Fatal("a response naming another device must be refused")
	}
}

// enrolWith enrols against a server answering a valid enrolment with the
// fields of override replaced (a nil value removes the field).
func enrolWith(t *testing.T, override map[string]any) (*Material, error) {
	t.Helper()
	ca := newTestCA(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			CSRPEM string `json:"csr_pem"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		resp := map[string]any{
			"cert_pem":          string(ca.signCSR(t, body.CSRPEM, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))),
			"team_id":           "01kpq7x2abcd34",
			"tunnel_identifier": "tun12345",
			"prefix":            "gw-01",
			"device_host":       "gw-01.factory.eu.localport.dev",
			"region":            "eu",
			"keys":              testKeys,
		}
		for k, v := range override {
			if v == nil {
				delete(resp, k)
			} else {
				resp[k] = v
			}
		}
		writeJSON(t, w, resp)
	}))
	t.Cleanup(srv.Close)
	return (&Client{BaseURL: srv.URL, HTTP: srv.Client()}).EnrolDevice(context.Background(), "lpj_x", 0, nil)
}

// The device host and region come off the network and name what the agent
// dials and prints: each must match its DNS grammar.
func TestEnrolDeviceRefusesAnInvalidHostOrRegion(t *testing.T) {
	for name, override := range map[string]map[string]any{
		"single label":     {"device_host": "gw-01"},
		"escape sequence":  {"device_host": "gw-01.\x1b[2Jexample.dev"},
		"long label":       {"device_host": strings.Repeat("a", 64) + ".example.dev"},
		"kelvin sign":      {"device_host": "gw-01.\u212aexample.dev"},
		"region with dot":  {"region": "eu.example.com"},
		"region with port": {"region": "eu:1"},
		"long region":      {"region": strings.Repeat("e", 49)},
	} {
		if _, err := enrolWith(t, override); err == nil {
			t.Errorf("%s: enrolment accepted %v", name, override)
		}
	}
	if m, err := enrolWith(t, map[string]any{"region": nil}); err != nil || m.Meta.Device.Region != "" {
		t.Fatalf("no region: %v, %v; want the default region", m, err)
	}
	// A fleet without a public domain has no device host.
	if m, err := enrolWith(t, map[string]any{"device_host": nil}); err != nil || m.Meta.Device.Host != "" {
		t.Fatalf("no host: %v, %v; want an empty host", m, err)
	}
	if m, err := enrolWith(t, map[string]any{"device_host": "GW-01.Example.dev"}); err != nil || m.Meta.Device.Host != "gw-01.example.dev" {
		t.Fatalf("mixed case host: %v, %v; want it stored lowercase", m, err)
	}
}

// A null or absent ticket key set is not stored, as FetchDeviceKeys refuses
// it; an empty one is a valid set.
func TestEnrolDeviceStoresNoNullKeySet(t *testing.T) {
	for name, keys := range map[string]any{"absent": nil, "null": map[string]any{"ticket_keys": nil}} {
		m, err := enrolWith(t, map[string]any{"keys": keys})
		if err != nil || m.DeviceKeys != nil {
			t.Fatalf("%s: %v, keys %+v; want enrolment without keys", name, err, m.DeviceKeys)
		}
	}
	m, err := enrolWith(t, map[string]any{"keys": map[string]any{"ticket_keys": []TicketKey{}}})
	if err != nil || m.DeviceKeys == nil || m.DeviceKeys.TicketKeys == nil {
		t.Fatalf("empty set: %v, keys %+v; want an empty set", err, m.DeviceKeys)
	}
}

// savedDevice stores a device credential whose certificate is valid over
// [notBefore, notAfter].
func savedDevice(t *testing.T, ca *testCA, notBefore, notAfter time.Time) (*Store, *ecdsa.PrivateKey) {
	t.Helper()
	key := testKey(t)
	renewAfter := notBefore.Add(notAfter.Sub(notBefore) * 2 / 3)
	store := &Store{Root: t.TempDir()}
	if _, err := store.Save(context.Background(), Material{
		CertPEM: ca.sign(t, &key.PublicKey, notBefore, notAfter),
		Key:     fileKey{key},
		Meta: Meta{
			APIURL: "https://api.localport.io", Source: SourceToken, RenewAfter: &renewAfter,
			Device: &DeviceInfo{Host: "gw-01.factory.eu.localport.dev", Region: "eu"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	return store, key
}

func TestEnrolDeviceRefusesACertificateForAnotherKey(t *testing.T) {
	ca := newTestCA(t)
	ca.wrongKey = true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			CSRPEM string `json:"csr_pem"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		writeJSON(t, w, map[string]any{
			"cert_pem":          string(ca.signCSR(t, body.CSRPEM, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))),
			"team_id":           "01kpq7x2abcd34",
			"tunnel_identifier": "tun12345",
			"prefix":            "gw-01",
		})
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	if _, err := client.EnrolDevice(context.Background(), "lpj_x", 0, nil); err == nil {
		t.Fatal("a certificate for another key must be refused")
	}
}

// A credential directory another account can write is refused on load.
func TestLoadRefusesAGroupWritableCredentialDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits carry no policy on Windows")
	}
	store := &Store{Root: t.TempDir()}
	ref, err := store.Save(context.Background(), credentialFor(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/client/deploy-prod"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store.Dir(ref), 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ref); !errors.Is(err, security.ErrUntrustedPath) {
		t.Fatalf("Load = %v, want ErrUntrustedPath", err)
	}
}

// Save gives up its wait for the renewal lock when the caller cancels.
func TestSaveStopsWaitingWhenTheContextEnds(t *testing.T) {
	ca := newTestCA(t)
	store, _ := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	release, held, err := store.tryLock(deviceRef)
	if err != nil || !held {
		t.Fatalf("lock: held=%v err=%v", held, err)
	}
	t.Cleanup(release)

	key := testKey(t)
	m := Material{
		CertPEM: ca.sign(t, &key.PublicKey, time.Now().Add(-time.Minute), time.Now().Add(time.Hour)),
		Key:     fileKey{key},
		Meta:    Meta{APIURL: "https://api.localport.io", Source: SourceToken},
	}
	ctx, cancel := context.WithCancel(context.Background())
	saved := make(chan error, 1)
	go func() {
		_, err := store.Save(ctx, m)
		saved <- err
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-saved:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Save = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Save kept waiting after its context ended")
	}
}

// The wait for the renewal lock is bounded.
func TestWaitLockGivesUpAfterItsBound(t *testing.T) {
	store, _ := savedDevice(t, newTestCA(t), time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	release, held, err := store.tryLock(deviceRef)
	if err != nil || !held {
		t.Fatalf("lock: held=%v err=%v", held, err)
	}
	t.Cleanup(release)

	// The waiter's own context ends the test's wait if the bound is ignored.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := store.waitLock(ctx, deviceRef, 300*time.Millisecond)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrRenewalInProgress) {
			t.Fatalf("waitLock = %v, want ErrRenewalInProgress", err)
		}
		if waited := time.Since(start); waited < 300*time.Millisecond {
			t.Fatalf("waited %s, want at least 300ms", waited)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waitLock ignored its bound")
	}
}

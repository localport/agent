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
	"fmt"
	"io/fs"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
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
	TicketKeys:   []TicketKey{testTicketKey("k1", 1)},
	RecordingKey: testRecordingKey(1),
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
	assertNoKeysIn(t, filepath.Join(store.Dir(ref), metaFile))
	if m.DeviceKeys == nil || !slices.Equal(m.DeviceKeys.TicketKeys, testKeys.TicketKeys) {
		t.Fatalf("enrolment keys = %+v", m.DeviceKeys)
	}
	if _, err := os.Stat(filepath.Join(store.Dir(ref), ticketKeysFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Save wrote %s: %v", ticketKeysFile, err)
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

// A renewal or enrolment response with a null or absent ticket_keys stores no
// set; an empty array is a valid one.
func TestIssuedKeysRefusesANullSet(t *testing.T) {
	if issuedKeys(nil) != nil || issuedKeys(&DeviceKeys{RecordingKey: testRecordingKey(1)}) != nil {
		t.Fatal("a null set was accepted")
	}
	if k := issuedKeys(&DeviceKeys{TicketKeys: []TicketKey{}}); k == nil {
		t.Fatal("an empty set was refused")
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

// renewServer answers /v1/devices/renew after checking the old-key proof
// (skipped when oldKey is nil), and refuses every other path.
// before, when given, runs first in every request.
func renewServer(t *testing.T, ca *testCA, oldKey *ecdsa.PrivateKey, before ...func()) (*httptest.Server, *[]string) {
	t.Helper()
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, f := range before {
			f()
		}
		paths = append(paths, r.URL.Path)
		if r.URL.Path != "/v1/devices/renew" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var body struct {
			CertPEM   string `json:"cert_pem"`
			CSRPEM    string `json:"csr_pem"`
			Signature string `json:"signature"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		leaf, err := leafOf([]byte(body.CertPEM))
		if err != nil {
			t.Fatal(err)
		}
		csrBlock, _ := pem.Decode([]byte(body.CSRPEM))
		sig, err := base64.StdEncoding.DecodeString(body.Signature)
		if err != nil {
			t.Fatal(err)
		}
		digest := renewalDigest(csrBlock.Bytes, time.Now().Unix()/60, leaf.SerialNumber.Text(16))
		if oldKey != nil && !ecdsa.VerifyASN1(&oldKey.PublicKey, digest, sig) {
			t.Error("renewal proof does not verify with the old key")
		}
		writeJSON(t, w, map[string]any{
			"cert_pem":    string(ca.signCSR(t, body.CSRPEM, time.Now().Add(-time.Minute), time.Now().Add(30*24*time.Hour))),
			"renew_after": time.Now().Add(20 * 24 * time.Hour).UTC().Format(time.RFC3339),
			"keys":        testKeys,
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &paths
}

// An expired device certificate is due now and renews at the device route.
// The result is pending; the expired one stays current until Promote.
func TestExpiredDeviceCertificateRenewsAtTheDeviceRoute(t *testing.T) {
	ca := newTestCA(t)
	store, oldKey := savedDevice(t, ca, time.Now().Add(-40*24*time.Hour), time.Now().Add(-time.Hour))
	srv, paths := renewServer(t, ca, oldKey)
	r := &Renewer{Store: store, Ref: deviceRef}

	cur, err := store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	due, ok, err := r.due(cur.Meta)
	if err != nil || !ok || time.Until(due) > 0 {
		t.Fatalf("due = %s ok=%v err=%v, want now", due, ok, err)
	}

	next, err := r.renewLocked(context.Background(), &Client{BaseURL: srv.URL, HTTP: srv.Client()}, cur)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if len(*paths) != 1 || (*paths)[0] != "/v1/devices/renew" {
		t.Fatalf("requests = %v, want one to /v1/devices/renew", *paths)
	}

	still, err := store.Load(deviceRef)
	if err != nil || still.Meta.Serial != cur.Meta.Serial {
		t.Fatalf("current changed before promotion: %v", err)
	}
	pending, err := store.LoadPending(deviceRef)
	if err != nil {
		t.Fatalf("LoadPending: %v", err)
	}
	if pending.Meta.Serial != next.Meta.Serial {
		t.Fatalf("pending serial = %s, want %s", pending.Meta.Serial, next.Meta.Serial)
	}
	if d := pending.Meta.Device; d == nil || d.Region != "eu" {
		t.Fatalf("pending device details = %+v: host and region carry over", d)
	}
	assertNoKeysIn(t, filepath.Join(store.Dir(deviceRef), pendingFile))
	if pub, ok := store.mustTicketKeys(deviceRef).Lookup("k1"); !ok || pub == nil {
		t.Fatal("the renewal response's keys must reach TicketKeys")
	}
	if _, err := pending.TLSCertificate(); err != nil {
		t.Fatalf("pending credential is unusable: %v", err)
	}

	// The pending renewal now governs the schedule.
	due, ok, err = r.due(cur.Meta)
	if err != nil || !ok || time.Until(due) < 24*time.Hour {
		t.Fatalf("due after renewal = %s ok=%v err=%v, want the pending renew_after", due, ok, err)
	}
}

func TestPromoteInstallsThePendingCredentialAndDropsTheOldKey(t *testing.T) {
	ca := newTestCA(t)
	store, oldKey := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	srv, _ := renewServer(t, ca, oldKey)
	r := &Renewer{Store: store, Ref: deviceRef}
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}

	if err := store.Promote(deviceRef, "abc"); !errors.Is(err, ErrNoPending) {
		t.Fatalf("Promote with nothing pending = %v, want ErrNoPending", err)
	}

	old, err := store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	first, err := r.renewLocked(context.Background(), client, old)
	if err != nil {
		t.Fatal(err)
	}
	// A second renewal before promotion replaces the pending one.
	second, err := r.renewLocked(context.Background(), client, old)
	if err != nil {
		t.Fatal(err)
	}
	dir := store.Dir(deviceRef)
	if _, err := os.Stat(filepath.Join(dir, "key-"+first.Meta.Serial+".pem")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a replaced pending key must be deleted")
	}
	if err := store.Promote(deviceRef, first.Meta.Serial); !errors.Is(err, ErrPendingChanged) {
		t.Fatalf("Promote(replaced serial) = %v, want ErrPendingChanged", err)
	}

	if err := store.Promote(deviceRef, second.Meta.Serial); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	cur, err := store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	if cur.Meta.Serial != second.Meta.Serial {
		t.Fatalf("current serial = %s, want the promoted %s", cur.Meta.Serial, second.Meta.Serial)
	}
	if _, err := store.LoadPending(deviceRef); !errors.Is(err, ErrNoPending) {
		t.Fatalf("LoadPending after Promote = %v, want ErrNoPending", err)
	}
	for _, name := range []string{old.Meta.Key.File, old.Meta.Cert} {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s survived promotion", name)
		}
	}
	// Repeating a completed promotion succeeds.
	if err := store.Promote(deviceRef, second.Meta.Serial); err != nil {
		t.Fatalf("repeated Promote = %v", err)
	}
}

// Promote and a renewal both rewrite the credential's files, so they share the
// renewal lock and Promote never interleaves with a renewal in flight.
func TestPromoteWaitsOutARenewalInFlight(t *testing.T) {
	ca := newTestCA(t)
	store, oldKey := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	srv, _ := renewServer(t, ca, oldKey)
	r := &Renewer{Store: store, Ref: deviceRef}
	old, err := store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	next, err := r.renewLocked(context.Background(), &Client{BaseURL: srv.URL, HTTP: srv.Client()}, old)
	if err != nil {
		t.Fatal(err)
	}

	release, held, err := r.lock()
	if err != nil || !held {
		t.Fatalf("lock: held=%v err=%v", held, err)
	}
	if err := store.Promote(deviceRef, next.Meta.Serial); !errors.Is(err, ErrRenewalInProgress) {
		t.Fatalf("Promote during a renewal = %v, want ErrRenewalInProgress", err)
	}
	release()
	if err := store.Promote(deviceRef, next.Meta.Serial); err != nil {
		t.Fatalf("Promote after the renewal = %v", err)
	}
}

// A renewal that finishes after the credential was replaced (a re-enrolment)
// must not attach its certificate to the new credential.
func TestPendingIsRefusedWhenTheCurrentCredentialChanged(t *testing.T) {
	ca := newTestCA(t)
	store, oldKey := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	srv, _ := renewServer(t, ca, oldKey)
	old, err := store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	next, err := (&Client{BaseURL: srv.URL, HTTP: srv.Client()}).Renew(context.Background(), old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.savePending(*next, "not-the-current-serial"); !errors.Is(err, ErrCredentialReplaced) {
		t.Fatalf("savePending = %v, want ErrCredentialReplaced", err)
	}
	if _, err := store.LoadPending(deviceRef); !errors.Is(err, ErrNoPending) {
		t.Fatalf("LoadPending = %v, want ErrNoPending", err)
	}
}

// A new enrolment replaces the whole credential, pending renewal included.
func TestSaveDiscardsAPendingRenewal(t *testing.T) {
	ca := newTestCA(t)
	store, oldKey := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	srv, _ := renewServer(t, ca, oldKey)
	old, err := store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&Renewer{Store: store, Ref: deviceRef}).renewLocked(context.Background(), &Client{BaseURL: srv.URL, HTTP: srv.Client()}, old); err != nil {
		t.Fatal(err)
	}
	key := testKey(t)
	if _, err := store.Save(context.Background(), Material{
		CertPEM: ca.sign(t, &key.PublicKey, time.Now().Add(-time.Minute), time.Now().Add(time.Hour)),
		Key:     fileKey{key},
		Meta:    Meta{APIURL: "https://api.localport.io", Source: SourceToken},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadPending(deviceRef); !errors.Is(err, ErrNoPending) {
		t.Fatalf("LoadPending after re-enrolment = %v, want ErrNoPending", err)
	}
	entries, err := os.ReadDir(store.Dir(deviceRef))
	if err != nil {
		t.Fatal(err)
	}
	var files int
	for _, e := range entries {
		if n := e.Name(); strings.HasPrefix(n, "cert-") || strings.HasPrefix(n, "key-") {
			files++
		}
	}
	if files != 2 {
		t.Fatalf("%d certificate and key files remain, want the new pair only", files)
	}
	// The ticket keys the renewal stored are not credential files and stay.
	if _, ok := store.mustTicketKeys(deviceRef).Lookup("k1"); !ok {
		t.Fatal("Save without keys dropped the stored ticket keys")
	}
	if _, err := os.Stat(filepath.Join(store.Dir(deviceRef), ticketKeysFile)); err != nil {
		t.Fatalf("%s did not survive Save: %v", ticketKeysFile, err)
	}
}

// Retry-After is honoured in full, plus jitter bounded by retryMaxDelay.
func TestRetryAfterWaitAddsBoundedJitter(t *testing.T) {
	err := &APIError{Status: http.StatusTooManyRequests, retryAfter: time.Minute}
	jittered := false
	for range 50 {
		wait, ok := retryAfterWait(err)
		if !ok || wait < time.Minute || wait > time.Minute+retryMaxDelay {
			t.Fatalf("wait = %s ok=%v, want [1m, 1m30s]", wait, ok)
		}
		jittered = jittered || wait > time.Minute
	}
	if !jittered {
		t.Fatal("50 waits all equal Retry-After: no jitter")
	}
	if _, ok := retryAfterWait(&APIError{Status: http.StatusServiceUnavailable}); ok {
		t.Fatal("no Retry-After, no server-directed wait")
	}
}

// renew_after past the expiry (a clock or server fault) must not postpone the
// renewal of an expired certificate.
func TestAnExpiredCertificateIsDueWhateverItsRenewAfter(t *testing.T) {
	store, _ := savedDevice(t, newTestCA(t), time.Now().Add(-48*time.Hour), time.Now().Add(-time.Minute))
	r := &Renewer{Store: store, Ref: deviceRef}
	cur, err := store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(24 * time.Hour)
	cur.Meta.RenewAfter = &later
	due, ok, err := r.due(cur.Meta)
	if err != nil || !ok || time.Until(due) > 0 {
		t.Fatalf("due = %s ok=%v err=%v, want now", due, ok, err)
	}
}

// A crash after a re-enrolment committed meta.json but before pending.json
// was removed must not resurrect the old pending certificate.
func TestPendingOfAReplacedCredentialIsIgnored(t *testing.T) {
	ca := newTestCA(t)
	store, oldKey := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	srv, _ := renewServer(t, ca, oldKey)
	old, err := store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&Renewer{Store: store, Ref: deviceRef}).renewLocked(context.Background(), &Client{BaseURL: srv.URL, HTTP: srv.Client()}, old); err != nil {
		t.Fatal(err)
	}
	pendingPath := filepath.Join(store.Dir(deviceRef), pendingFile)
	stale, err := os.ReadFile(pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	key := testKey(t)
	if _, err := store.Save(context.Background(), Material{
		CertPEM: ca.sign(t, &key.PublicKey, time.Now().Add(-time.Minute), time.Now().Add(time.Hour)),
		Key:     fileKey{key},
		Meta:    Meta{APIURL: "https://api.localport.io", Source: SourceToken},
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pendingPath, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadPending(deviceRef); !errors.Is(err, ErrNoPending) {
		t.Fatalf("LoadPending = %v, want ErrNoPending", err)
	}
}

// Save waits for a renewal in flight instead of committing under it, so
// neither sweeps the other's files.
func TestSaveWaitsForARenewalInFlight(t *testing.T) {
	ca := newTestCA(t)
	entered := make(chan struct{})
	unblock := make(chan struct{})
	var unblockOnce sync.Once
	release := func() { unblockOnce.Do(func() { close(unblock) }) }
	store, oldKey := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	srv, _ := renewServer(t, ca, oldKey, func() {
		close(entered)
		<-unblock
	})
	// Runs before the server's Close, so a failing test does not hang on the
	// blocked handler.
	t.Cleanup(release)
	r := &Renewer{Store: store, Ref: deviceRef}
	old, err := store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}

	renewed := make(chan error, 1)
	go func() {
		release, held, err := r.lock()
		if err != nil || !held {
			renewed <- fmt.Errorf("lock: held=%v err=%v", held, err)
			close(entered)
			return
		}
		defer release()
		_, err = r.renewLocked(context.Background(), &Client{BaseURL: srv.URL, HTTP: srv.Client()}, old)
		renewed <- err
	}()
	<-entered

	key := testKey(t)
	replacement := Material{
		CertPEM: ca.sign(t, &key.PublicKey, time.Now().Add(-time.Minute), time.Now().Add(time.Hour)),
		Key:     fileKey{key},
		Meta:    Meta{APIURL: "https://api.localport.io", Source: SourceToken},
	}
	saved := make(chan error, 1)
	go func() {
		_, err := store.Save(context.Background(), replacement)
		saved <- err
	}()
	select {
	case err := <-saved:
		t.Fatalf("Save returned (%v) while a renewal held the lock", err)
	case <-time.After(500 * time.Millisecond):
	}
	release()
	if err := <-renewed; err != nil {
		t.Fatalf("renewal: %v", err)
	}
	if err := <-saved; err != nil {
		t.Fatalf("Save: %v", err)
	}

	cur, err := store.Load(deviceRef)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := cur.TLSCertificate(); err != nil {
		t.Fatalf("the saved credential lost a file: %v", err)
	}
	if _, err := store.LoadPending(deviceRef); !errors.Is(err, ErrNoPending) {
		t.Fatalf("LoadPending = %v, want ErrNoPending after the re-enrolment", err)
	}
}

// A renewal response must certify the generated key for the same credential.
func TestRenewRefusesACertificateForAnotherKeyOrIdentity(t *testing.T) {
	for name, broken := range map[string]func(*testCA){
		"another key":      func(ca *testCA) { ca.wrongKey = true },
		"another identity": func(ca *testCA) { ca.uri = "spiffe://01kpq7x2abcd34.mtls.localport.dev/device/tun12345/other" },
	} {
		t.Run(name, func(t *testing.T) {
			ca := newTestCA(t)
			store, oldKey := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
			broken(ca)
			srv, _ := renewServer(t, ca, oldKey)
			old, err := store.Load(deviceRef)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := (&Client{BaseURL: srv.URL, HTTP: srv.Client()}).Renew(context.Background(), old); err == nil {
				t.Fatal("Renew must refuse the response")
			}
		})
	}
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

// Promote refuses a pending credential whose files do not load, leaving the
// current one in place.
func TestPromoteRefusesAnUnusablePendingCredential(t *testing.T) {
	ca := newTestCA(t)
	store, oldKey := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	srv, _ := renewServer(t, ca, oldKey)
	old, err := store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	next, err := (&Renewer{Store: store, Ref: deviceRef}).renewLocked(context.Background(), &Client{BaseURL: srv.URL, HTTP: srv.Client()}, old)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(store.Dir(deviceRef), "key-"+next.Meta.Serial+".pem")); err != nil {
		t.Fatal(err)
	}
	if err := store.Promote(deviceRef, next.Meta.Serial); err == nil {
		t.Fatal("Promote must refuse a pending credential without its key")
	}
	cur, err := store.Load(deviceRef)
	if err != nil || cur.Meta.Serial != old.Meta.Serial {
		t.Fatalf("current changed: serial %v err %v", cur, err)
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

// renewedDevice stores a device credential and one pending renewal of it.
func renewedDevice(t *testing.T) (store *Store, old, next *Material) {
	t.Helper()
	ca := newTestCA(t)
	store, oldKey := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	srv, _ := renewServer(t, ca, oldKey)
	old, err := store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	next, err = (&Renewer{Store: store, Ref: deviceRef}).renewLocked(context.Background(), &Client{BaseURL: srv.URL, HTTP: srv.Client()}, old)
	if err != nil {
		t.Fatal(err)
	}
	return store, old, next
}

// A crash between Promote's meta.json write and its pending.json removal
// leaves the superseded pair behind. Promoting again finishes the cleanup.
func TestPromoteAgainCleansUpAfterAnInterruptedPromote(t *testing.T) {
	store, old, next := renewedDevice(t)
	dir := store.Dir(deviceRef)
	pending, err := store.LoadPending(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	// The first half of Promote, then the crash.
	promoted := pending.Meta
	promoted.RenewedFrom = ""
	if err := writeMeta(dir, metaFile, promoted); err != nil {
		t.Fatal(err)
	}

	if err := store.Promote(deviceRef, next.Meta.Serial); err != nil {
		t.Fatalf("Promote after the crash = %v", err)
	}
	for _, name := range []string{pendingFile, old.Meta.Cert, old.Meta.Key.File} {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s survived the repeated Promote", name)
		}
	}
	if cur, err := store.Load(deviceRef); err != nil || cur.Meta.Serial != next.Meta.Serial {
		t.Fatalf("current = %v, %v; want the promoted serial", cur, err)
	}
}

// Promote refuses a pending record whose key file holds another pair's key.
func TestPromoteRefusesAPendingKeyThatDoesNotMatchItsCertificate(t *testing.T) {
	store, old, next := renewedDevice(t)
	other, err := fileKey{testKey(t)}.marshal()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(store.Dir(deviceRef), "key-"+next.Meta.Serial+".pem")
	if err := security.WritePrivateFileAtomic(keyPath, other); err != nil {
		t.Fatal(err)
	}
	if err := store.Promote(deviceRef, next.Meta.Serial); err == nil {
		t.Fatal("Promote must refuse a pending key that does not match its certificate")
	}
	if cur, err := store.Load(deviceRef); err != nil || cur.Meta.Serial != old.Meta.Serial {
		t.Fatalf("current changed: %v, %v", cur, err)
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

// Repeating the Promote of the current serial after a later renewal must keep
// that renewal pending, not report it as a replaced pending credential.
func TestPromoteOfTheCurrentSerialKeepsALaterRenewalPending(t *testing.T) {
	ca := newTestCA(t)
	store, _ := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	srv, _ := renewServer(t, ca, nil)
	r := &Renewer{Store: store, Ref: deviceRef}
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}

	renew := func() *Material {
		t.Helper()
		cur, err := store.Load(deviceRef)
		if err != nil {
			t.Fatal(err)
		}
		next, err := r.renewLocked(context.Background(), client, cur)
		if err != nil {
			t.Fatal(err)
		}
		return next
	}
	x := renew()
	if err := store.Promote(deviceRef, x.Meta.Serial); err != nil {
		t.Fatalf("Promote(X) = %v", err)
	}
	y := renew()

	if err := store.Promote(deviceRef, x.Meta.Serial); err != nil {
		t.Fatalf("repeated Promote(X) with Y pending = %v, want nil", err)
	}
	pending, err := store.LoadPending(deviceRef)
	if err != nil || pending.Meta.Serial != y.Meta.Serial {
		t.Fatalf("pending after the repeated Promote = %v, %v; want Y kept", pending, err)
	}
}

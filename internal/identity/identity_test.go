package identity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The renewal digest is the one value the agent and the control plane must
// compute identically. A mismatch is silent, renewal simply never succeeds and
// the credential expires weeks later, so this vector is pinned here and checked
// against the same one on the far side.
const goldenDigest = "bb21b93bb7ddd5f72c67c1a2b127f99322456fd06b00242a65791b6b9cbe80ff"

func TestRenewalDigestMatchesTheServerVector(t *testing.T) {
	got := hex.EncodeToString(renewalDigest([]byte("csr-der-bytes"), 29000000, "beef"))
	if got != goldenDigest {
		t.Fatalf("renewal digest drifted from the server:\n got %s\nwant %s", got, goldenDigest)
	}
}

func TestRenewalDigestBindsToTheCertificateAndTheMinute(t *testing.T) {
	base := renewalDigest([]byte("csr"), 100, "aa")
	for _, tc := range []struct {
		name   string
		digest []byte
	}{
		{"different csr", renewalDigest([]byte("other"), 100, "aa")},
		{"different minute", renewalDigest([]byte("csr"), 101, "aa")},
		{"different serial", renewalDigest([]byte("csr"), 100, "bb")},
	} {
		if string(tc.digest) == string(base) {
			t.Errorf("%s produced the same digest: a captured renewal would replay", tc.name)
		}
	}
}

func TestRefFromCertReadsTheCertificate(t *testing.T) {
	for _, tc := range []struct {
		uri  string
		want Ref
	}{
		{
			"spiffe://team_abc123.mtls.localport.dev/client/deploy-prod",
			Ref{Team: "team_abc123", Kind: KindClient, Identity: "deploy-prod"},
		},
		{
			"spiffe://team_abc123.mtls.localport.dev/user/0mkppnsc7lsdcv",
			Ref{Team: "team_abc123", Kind: KindUser, Identity: "0mkppnsc7lsdcv"},
		},
		{
			// A device carries its tunnel between kind and identity.
			"spiffe://team_abc123.mtls.localport.dev/device/tun12345/gw-01",
			Ref{Team: "team_abc123", Kind: KindDevice, Identity: "gw-01"},
		},
	} {
		got, err := RefFromCert(selfSigned(t, tc.uri))
		if err != nil {
			t.Fatalf("RefFromCert(%s): %v", tc.uri, err)
		}
		if got != tc.want {
			t.Fatalf("RefFromCert(%s) = %+v, want %+v", tc.uri, got, tc.want)
		}
	}
}

func TestRefFromCertRefusesAForeignURI(t *testing.T) {
	// A trusted CA can put arbitrary URIs in a SAN. Anything that is not our
	// trust-domain shape must not be mistaken for a team, or the credential
	// lands in a directory named after someone else's string.
	leaf := selfSigned(t, "spiffe://example.com/client/whoever")
	if _, err := RefFromCert(leaf); err == nil {
		t.Fatal("expected a non-Localport SPIFFE ID to be refused")
	}
}

func TestSaveWritesKeyMaterialUnreadableByOthers(t *testing.T) {
	store := &Store{Root: t.TempDir()}
	ref, err := store.Save(credentialFor(t, "spiffe://team_x.mtls.localport.dev/client/deploy-prod"))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	for _, name := range []string{keyFile, certFile, metaFile} {
		info, err := os.Stat(filepath.Join(store.Dir(ref), name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s mode %#o is readable by group or other", name, perm)
		}
	}
	dir, err := os.Stat(store.Dir(ref))
	if err != nil {
		t.Fatal(err)
	}
	if perm := dir.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("credential directory mode %#o is readable by group or other", perm)
	}

	got, err := store.Load(ref)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Meta.Identity != "deploy-prod" || got.Meta.Team != "team_x" || got.Meta.Kind != KindClient {
		t.Fatalf("metadata round trip lost data: %+v", got.Meta)
	}
}

// `localport login` and `localport setup` must resolve to different
// directories: one replacing the other would swap the principal a running
// connect presents.
func TestSignInAndSetupTokenDoNotOverwriteEachOther(t *testing.T) {
	store := &Store{Root: t.TempDir()}

	machine := credentialFor(t, "spiffe://team_x.mtls.localport.dev/client/deploy-prod")
	machine.Meta.Source = SourceToken
	person := credentialFor(t, "spiffe://team_x.mtls.localport.dev/user/0mkppnsc7lsdcv")
	person.Meta.Source = SourceSSO

	machineRef, err := store.Save(machine)
	if err != nil {
		t.Fatal(err)
	}
	personRef, err := store.Save(person)
	if err != nil {
		t.Fatal(err)
	}
	if machineRef == personRef {
		t.Fatal("a machine setup token and a sign-in resolved to the same credential")
	}

	refs, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 {
		t.Fatalf("store holds %d credentials, want 2: %+v", len(refs), refs)
	}
	// Both must still be intact and still be themselves.
	for ref, want := range map[Ref]Source{machineRef: SourceToken, personRef: SourceSSO} {
		m, err := store.Load(ref)
		if err != nil {
			t.Fatalf("Load(%s): %v", ref, err)
		}
		if m.Meta.Source != want {
			t.Fatalf("%s has source %q, want %q", ref, m.Meta.Source, want)
		}
	}
}

func TestResolveRefusesToGuessBetweenIdentities(t *testing.T) {
	store := &Store{Root: t.TempDir()}
	for _, uri := range []string{
		"spiffe://team_a.mtls.localport.dev/client/deploy-prod",
		"spiffe://team_b.mtls.localport.dev/client/deploy-prod",
	} {
		if _, err := store.Save(credentialFor(t, uri)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Resolve(Selector{}); err == nil {
		t.Fatal("expected Resolve to refuse rather than pick one of two identities")
	}
	// The identity is the same on both, so it cannot disambiguate on its own.
	if _, err := store.Resolve(Selector{Identity: "deploy-prod"}); err == nil {
		t.Fatal("expected an ambiguous identity to be refused")
	}
	got, err := store.Resolve(Selector{Team: "team_b"})
	if err != nil {
		t.Fatalf("Resolve(team_b): %v", err)
	}
	if got.Team != "team_b" {
		t.Fatalf("Resolve(team_b) = %+v", got)
	}
}

// A renewal carries the identity forward, so a changed principal means the file
// was replaced by something else. Presenting it would authenticate this process
// as another party and attribute its traffic to them.
func TestReloadRefusesASwappedPrincipal(t *testing.T) {
	store := &Store{Root: t.TempDir()}
	ref, err := store.Save(credentialFor(t, "spiffe://team_x.mtls.localport.dev/client/deploy-prod"))
	if err != nil {
		t.Fatal(err)
	}
	cred, err := Open(store, Selector{})
	if err != nil {
		t.Fatal(err)
	}
	before, err := cred.Certificate()
	if err != nil {
		t.Fatal(err)
	}

	// Overwrite in place with a different principal, as the old team-keyed
	// layout did whenever the other command ran.
	other := credentialFor(t, "spiffe://team_x.mtls.localport.dev/user/0mkppnsc7lsdcv")
	otherKeyPEM, err := other.Key.(persistentKey).marshal()
	if err != nil {
		t.Fatal(err)
	}
	dir := store.Dir(ref)
	for name, data := range map[string][]byte{certFile: other.CertPEM, keyFile: otherKeyPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cred.lastStat = time.Time{} // force the next Certificate() to re-stat

	after, err := cred.Certificate()
	if err != nil {
		t.Fatalf("a refused reload must keep serving the credential we opened with: %v", err)
	}
	if after.Leaf.SerialNumber.Cmp(before.Leaf.SerialNumber) != 0 {
		t.Fatal("reload adopted a different principal from disk")
	}
}

// Components are used verbatim, and a component that could escape the store is
// refused rather than repaired.
//
// The Ref is built from a certificate, so `..` in an identity is the case that
// matters: repairing it would file the credential under a name that is not the
// one the certificate carries.
func TestRefRefusesComponentsThatEscapeTheStore(t *testing.T) {
	base := Ref{Team: "01kppnsc7lsdcv", Kind: KindClient, Identity: "deploy-prod"}
	if !base.valid() {
		t.Fatal("an ordinary ref must be valid")
	}
	if got := base.dir(); got != "01kppnsc7lsdcv/client-deploy-prod" {
		t.Fatalf("dir() = %q; components are used verbatim", got)
	}

	for name, ref := range map[string]Ref{
		"traversing identity": {Team: "t", Kind: KindClient, Identity: ".."},
		"traversing team":     {Team: "..", Kind: KindClient, Identity: "a"},
		"dot identity":        {Team: "t", Kind: KindClient, Identity: "."},
		"separator in team":   {Team: "a/b", Kind: KindClient, Identity: "a"},
		"separator in ident":  {Team: "t", Kind: KindClient, Identity: `a\b`},
		"empty team":          {Team: "", Kind: KindClient, Identity: "a"},
		"empty identity":      {Team: "t", Kind: KindClient, Identity: ""},
	} {
		if ref.valid() {
			t.Errorf("%s: must be refused, not filed under a repaired name", name)
		}
	}
}

// The setup token is a bearer secret. Sending it over http is the one mistake
// that cannot be undone afterwards, so there is no host it is allowed for.
func TestNewClientRefusesPlaintext(t *testing.T) {
	for _, raw := range []string{
		"http://api.example.com",
		"http://localhost:8080",
		"http://127.0.0.1:8080",
	} {
		if _, err := NewClient(raw); err == nil {
			t.Errorf("NewClient(%q) must refuse plain http", raw)
		}
	}
	if _, err := NewClient("https://api.example.com"); err != nil {
		t.Fatalf("https must be accepted: %v", err)
	}
}

func TestDefaultRenewAfterLeavesARetryBudget(t *testing.T) {
	start := time.Now()
	end := start.Add(30 * 24 * time.Hour)
	got := defaultRenewAfter(start, end)
	if !got.After(start) || !got.Before(end) {
		t.Fatalf("renew_after %s is outside the certificate lifetime", got)
	}
	if remaining := end.Sub(got); remaining < 9*24*time.Hour {
		t.Fatalf("retry budget %s is under a third of the lifetime", remaining)
	}
}

// A sign-in must never reach the renewal endpoint. The server refuses it; this
// is what stops the agent from asking.
func TestRenewNeverCallsTheServerForASignInCredential(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Built directly rather than through NewClient, which enforces https. This
	// test is about the refusal, not transport policy.
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}

	signIn := &Material{
		CertPEM: []byte("unused: the refusal happens before anything is parsed"),
		Meta:    Meta{Identity: "jane@acme.com", Source: SourceSSO},
	}
	_, err := client.Renew(context.Background(), signIn)
	if !errors.Is(err, ErrNotRenewable) {
		t.Fatalf("Renew(sso) = %v, want ErrNotRenewable", err)
	}
	if calls != 0 {
		t.Fatalf("the agent made %d request(s) to renew a sign-in; it must make none", calls)
	}

	// A property of the source, not of a caller remembering to check.
	machine := &Material{Meta: Meta{Source: SourceToken}}
	if _, err := client.Renew(context.Background(), machine); errors.Is(err, ErrNotRenewable) {
		t.Fatal("a token credential must still renew")
	}
}

// The device flow sends no renew_after; synthesizing one gave an 8-hour sign-in
// the renewal schedule of a machine set up with a setup token.
func TestSignInMaterialCarriesNoRenewalDeadline(t *testing.T) {
	leaf := selfSigned(t, "spiffe://team_abc123.mtls.localport.dev/user/0mkppnsc7lsdcv")
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	client := &Client{BaseURL: "https://api.localport.io"}

	signIn, err := client.assemble(fileKey{testKey(t)}, issuedMaterial{CertPEM: certPEM, Source: SourceSSO})
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if signIn.Meta.Source != SourceSSO {
		t.Fatalf("source = %q, want %q: nothing downstream can tell a person from a machine without it",
			signIn.Meta.Source, SourceSSO)
	}
	// Absent, not zero. A zero time serialises as year 1 and reads as a corrupt
	// record to anyone opening meta.json; the field is simply not written.
	if signIn.Meta.RenewAfter != nil {
		t.Fatalf("renew_after = %s, but the control plane sent none", *signIn.Meta.RenewAfter)
	}
	if _, renews := signIn.Meta.NextRenewal(); renews {
		t.Fatal("a sign-in must report that it does not renew, not a timestamp")
	}

	// The fallback still protects a machine, where nobody is watching.
	machine, err := client.assemble(fileKey{testKey(t)}, issuedMaterial{CertPEM: certPEM, Source: SourceToken})
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if _, renews := machine.Meta.NextRenewal(); !renews {
		t.Fatal("a machine credential lost its renewal fallback")
	}
}

func selfSigned(t *testing.T, uri string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := leafOf(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// The device-flow poll is driven by the codes the control plane returns, so the
// two sides have to agree on them. A mismatch is silent and sign-in simply stops
// working, which is why the values are pinned here rather than assumed.
func TestLoginPollingIsDrivenByControlPlaneErrorCodes(t *testing.T) {
	if codeAuthorizationPending != "SE021" || codeSlowDown != "SE022" {
		t.Fatalf("polling codes drifted from the control plane: pending=%q slow_down=%q",
			codeAuthorizationPending, codeSlowDown)
	}

	// Sequence: pending, slow_down, then the certificate. The loop must survive
	// the first two and only stop on the third.
	leaf := selfSigned(t, "spiffe://team_abc123.mtls.localport.dev/user/0mkppnsc7lsdcv")
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))

	var polls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/mtls/device/start" {
			w.WriteHeader(http.StatusCreated)
			// The server owns the cadence, so the test sets a fast one rather
			// than sleeping through the production default.
			fmt.Fprint(w, `{"device_code":"dc","user_code":"ABCD-EFGH","interval":1,"expires_in":600}`)
			return
		}
		polls++
		switch polls {
		case 1:
			w.WriteHeader(http.StatusPreconditionRequired)
			fmt.Fprint(w, `{"code":"SE021","error":"Authorization Pending","message":"Waiting for approval in the dashboard"}`)
		case 2:
			w.WriteHeader(http.StatusPreconditionRequired)
			fmt.Fprint(w, `{"code":"SE022","error":"Polling Too Fast","message":"Polling faster than the interval"}`)
		default:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"cert_pem":%q,"identity":"jane@acme.com"}`, certPEM)
		}
	}))
	defer srv.Close()

	// Built directly rather than through NewClient, which enforces https. These
	// tests are about the poll's branching, not transport policy.
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	// The floor is 5s per poll, so drive the loop with a deadline of its own
	// rather than waiting on the real one.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	material, err := client.Login(ctx, nil)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if polls != 3 {
		t.Fatalf("polled %d times, want 3: the loop must treat SE021 and SE022 as non-terminal", polls)
	}
	if material.Meta.Source != SourceSSO {
		t.Fatalf("source = %q, want %q", material.Meta.Source, SourceSSO)
	}
}

// An error the agent does not recognise must stop the loop. Treating an unknown
// refusal as "keep waiting" would poll a refusing endpoint until the sign-in
// expired, with nothing on screen explaining why.
func TestLoginStopsOnAnUnrecognisedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/mtls/device/start" {
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"device_code":"dc","user_code":"ABCD-EFGH","interval":1,"expires_in":600}`)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"code":"VAL001","error":"Input Error","message":"That sign-in is no longer valid."}`)
	}))
	defer srv.Close()

	// Built directly rather than through NewClient, which enforces https. These
	// tests are about the poll's branching, not transport policy.
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := client.Login(ctx, nil); err == nil {
		t.Fatal("expected an unrecognised refusal to end the loop")
	} else if !strings.Contains(err.Error(), "VAL001") {
		t.Fatalf("the support code must reach the operator, got %v", err)
	}
}

// credentialFor builds a self-signed leaf and the key that matches it, so a
// Material round-trips through Save, Load and tls.X509KeyPair.
func credentialFor(t *testing.T, uri string) Material {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return Material{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Key:     fileKey{key},
		// Source has to be set: Save validates the record it writes, so a helper
		// that omitted it would be testing against a credential the store refuses.
		Meta: Meta{APIURL: "https://api.localport.io", Source: SourceToken},
	}
}

// Two writers renewing minutes apart issue two certificates where one is
// immediately orphaned, which walks the identity through its live-certificate
// cap until it can no longer renew at all. flock is held per open file
// description, so a second holder conflicts even inside one process.
func TestRenewalLockAdmitsOneWriter(t *testing.T) {
	store := &Store{Root: t.TempDir()}
	ref, err := store.Save(credentialFor(t, "spiffe://team_x.mtls.localport.dev/client/deploy-prod"))
	if err != nil {
		t.Fatal(err)
	}
	r := &Renewer{Store: store, Ref: ref}

	release, held, err := r.lock()
	if err != nil || !held {
		t.Fatalf("first lock: held=%v err=%v", held, err)
	}
	if _, held, err := r.lock(); err != nil || held {
		t.Fatalf("second lock: held=%v err=%v, want held=false", held, err)
	}
	if _, err := r.RenewOnce(context.Background()); !errors.Is(err, ErrRenewalInProgress) {
		t.Fatalf("RenewOnce while locked = %v, want ErrRenewalInProgress", err)
	}

	release()
	release2, held, err := r.lock()
	if err != nil || !held {
		t.Fatalf("lock after release: held=%v err=%v", held, err)
	}
	release2()
}

// systemd sets $HOME only for a unit that names a User=, so a service without
// one runs with none. Failing there would leave the most common machine
// deployment unable to hold a credential at all.
func TestDefaultRootFallsBackWhenThereIsNoHome(t *testing.T) {
	t.Setenv(HomeEnv, "")
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	t.Setenv("ProgramData", `C:\ProgramData`)

	root, err := defaultRoot()
	if err != nil {
		t.Fatalf("defaultRoot with no home: %v", err)
	}
	want := map[string]string{
		"windows": filepath.Join(`C:\ProgramData`, "localport"),
		"darwin":  "/Library/Application Support/localport",
	}[runtime.GOOS]
	if want == "" {
		want = "/var/lib/localport"
	}
	if root != want {
		t.Fatalf("defaultRoot = %q, want %q", root, want)
	}
}

func TestHomeEnvOverridesEverything(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(HomeEnv, dir)
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "identity"); store.Root != want {
		t.Fatalf("Root = %q, want %q", store.Root, want)
	}
}

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// Renewal proves possession by signing with the credential's existing key.
// Routing that through crypto.Signer instead of ecdsa.SignASN1 must not change
// the bytes on the wire: a mismatch here is silent, and renewal would
// never succeed until the certificate expired.
func TestSignerProducesTheSameSignatureFormatAsSignASN1(t *testing.T) {
	key := testKey(t)
	digest := renewalDigest([]byte("csr-der-bytes"), 29000000, "beef")

	viaSigner, err := fileKey{key}.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, digest, viaSigner) {
		t.Fatal("signature from crypto.Signer is not the ASN.1 DER the server verifies")
	}

	direct, err := ecdsa.SignASN1(rand.Reader, key, digest)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, digest, direct) {
		t.Fatal("control signature failed to verify")
	}
}

// A hardware key has no bytes to write. Only a key that says it is persistent
// leaves a key.pem behind, and Load must find whatever Save wrote.
func TestSaveRoundTripsTheKeyBacking(t *testing.T) {
	store := &Store{Root: t.TempDir()}
	ref, err := store.Save(credentialFor(t, "spiffe://team_x.mtls.localport.dev/client/deploy-prod"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(store.Dir(ref), keyFile)); err != nil {
		t.Fatalf("a file-backed key must leave key.pem: %v", err)
	}

	m, err := store.Load(ref)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Meta.Key.Backing; got != BackingFile {
		t.Fatalf("meta records backing %q, want %q", got, BackingFile)
	}
	if _, err := m.TLSCertificate(); err != nil {
		t.Fatalf("TLSCertificate: %v", err)
	}
}

// A stored record must never carry a timestamp that means "no value".
//
// Go's zero time is a real instant, so a sentinel serialises as
// "0001-01-01T00:00:00Z", a date that looks like data, reads as a corrupt
// record, and is in the past, so anything scheduling off it fires immediately
// and keeps firing.
func TestStoredMetadataNeverCarriesAZeroTimestamp(t *testing.T) {
	store := &Store{Root: t.TempDir()}
	cred := credentialFor(t, "spiffe://team_x.mtls.localport.dev/user/0mkppnsc7lsdcv")
	cred.Meta.Source = SourceSSO

	ref, err := store.Save(cred)
	if err != nil {
		t.Fatalf("save: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(store.Dir(ref), metaFile))
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	if bytes.Contains(raw, []byte("0001-01-01")) {
		t.Fatalf("meta.json carries a zero timestamp:\n%s", raw)
	}
	// Absent, not present-and-empty: a sign-in has no renewal at all.
	if bytes.Contains(raw, []byte("renew_after")) {
		t.Fatalf("a credential that does not renew must omit renew_after:\n%s", raw)
	}

	loaded, err := store.Load(ref)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, renews := loaded.Meta.NextRenewal(); renews {
		t.Fatal("a sign-in must report that it does not renew")
	}
	if loaded.Meta.NotAfter.IsZero() {
		t.Fatal("expiry must be derived from the certificate, not left to the caller")
	}
}

// Parsing is not validation. A record that survives json.Unmarshal but names an
// enum this build does not know describes a credential that cannot work, and it
// fails later, at a handshake, far from the file that caused it.
func TestUnusableMetadataIsRefusedOnRead(t *testing.T) {
	for name, meta := range map[string]Meta{
		"unknown kind":        {Identity: "a", Team: "t", Kind: "sideways", Source: SourceToken, NotAfter: time.Now()},
		"unknown source":      {Identity: "a", Team: "t", Kind: KindClient, Source: "magic", NotAfter: time.Now()},
		"no expiry":           {Identity: "a", Team: "t", Kind: KindClient, Source: SourceToken},
		"no identity":         {Team: "t", Kind: KindClient, Source: SourceToken, NotAfter: time.Now()},
		"sso with a deadline": {Identity: "a", Team: "t", Kind: KindUser, Source: SourceSSO, NotAfter: time.Now(), RenewAfter: ptr(time.Now())},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, metaFile)
			raw, err := json.Marshal(meta)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readMeta(path); err == nil {
				t.Fatalf("readMeta accepted an unusable record (%s)", name)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

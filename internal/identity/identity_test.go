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

	"github.com/localport/agent/internal/errcode"
)

// The renewal digest is the one value the agent and the control plane must
// compute identically. A mismatch is silent: renewal never succeeds and
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
			"spiffe://01kpq7x2abcd34.mtls.localport.dev/client/deploy-prod",
			Ref{Team: "01kpq7x2abcd34", Kind: KindClient, Identity: "deploy-prod"},
		},
		{
			"spiffe://01kpq7x2abcd34.mtls.localport.dev/user/0mkppnsc7lsdcv",
			Ref{Team: "01kpq7x2abcd34", Kind: KindUser, Identity: "0mkppnsc7lsdcv"},
		},
		{
			// A device carries its tunnel between kind and identity.
			"spiffe://01kpq7x2abcd34.mtls.localport.dev/device/tun12345/gw-01",
			Ref{Team: "01kpq7x2abcd34", Kind: KindDevice, Identity: "tun12345.gw-01"},
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
	// A trusted CA can put arbitrary URIs in a SAN. Anything not in Localport's
	// trust-domain shape must not be mistaken for a team, or the credential
	// lands in a directory named after someone else's string.
	leaf := selfSigned(t, "spiffe://example.com/client/whoever")
	if _, err := RefFromCert(leaf); err == nil {
		t.Fatal("expected a non-Localport SPIFFE ID to be refused")
	}
}

func TestSaveWritesKeyMaterialUnreadableByOthers(t *testing.T) {
	store := &Store{Root: t.TempDir()}
	ref, err := store.Save(context.Background(), credentialFor(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/client/deploy-prod"))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	meta, err := readMeta(filepath.Join(store.Dir(ref), metaFile))
	if err != nil {
		t.Fatal(err)
	}
	// On Windows Go derives mode bits from FILE_ATTRIBUTE_READONLY only. The
	// DACL is checked by Load below.
	if runtime.GOOS != "windows" {
		for _, name := range []string{meta.Key.File, meta.Cert, metaFile} {
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
	}

	got, err := store.Load(ref)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Meta.Identity != "deploy-prod" || got.Meta.Team != "01kpq7x2abcd34" || got.Meta.Kind != KindClient {
		t.Fatalf("metadata round trip lost data: %+v", got.Meta)
	}
}

// `localport login` and `localport setup` credentials live in different directories.
func TestSignInAndSetupTokenDoNotOverwriteEachOther(t *testing.T) {
	store := &Store{Root: t.TempDir()}

	machine := credentialFor(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/client/deploy-prod")
	machine.Meta.Source = SourceToken
	person := credentialFor(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/user/0mkppnsc7lsdcv")
	person.Meta.Source = SourceSSO

	machineRef, err := store.Save(context.Background(), machine)
	if err != nil {
		t.Fatal(err)
	}
	personRef, err := store.Save(context.Background(), person)
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
	// Both credentials are unchanged.
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
		"spiffe://02mfr8y3bcde45.mtls.localport.dev/client/deploy-prod",
		"spiffe://03ngs9z4cdef56.mtls.localport.dev/client/deploy-prod",
	} {
		if _, err := store.Save(context.Background(), credentialFor(t, uri)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Resolve(Selector{}); err == nil {
		t.Fatal("expected Resolve to refuse rather than pick one of two identities")
	}
	// Both share the identity, so it alone is ambiguous.
	if _, err := store.Resolve(Selector{Identity: "deploy-prod"}); err == nil {
		t.Fatal("expected an ambiguous identity to be refused")
	}
	got, err := store.Resolve(Selector{Team: "03ngs9z4cdef56"})
	if err != nil {
		t.Fatalf("Resolve(03ngs9z4cdef56): %v", err)
	}
	if got.Team != "03ngs9z4cdef56" {
		t.Fatalf("Resolve(03ngs9z4cdef56) = %+v", got)
	}
}

// A reloaded certificate with a different principal is refused. Renewal keeps
// the identity, so a change means another credential replaced the file.
func TestReloadRefusesASwappedPrincipal(t *testing.T) {
	store := &Store{Root: t.TempDir()}
	ref, err := store.Save(context.Background(), credentialFor(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/client/deploy-prod"))
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

	// Overwrite the file with a different principal.
	other := credentialFor(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/user/0mkppnsc7lsdcv")
	otherKeyPEM, err := other.Key.(persistentKey).marshal()
	if err != nil {
		t.Fatal(err)
	}
	dir := store.Dir(ref)
	meta, err := readMeta(filepath.Join(dir, metaFile))
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{meta.Cert: other.CertPEM, meta.Key.File: otherKeyPEM} {
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

// Components are used verbatim. A component that could escape the store, such
// as `..`, is refused and not repaired.
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

// A sign-in or a CI workload credential must never reach the renewal
// endpoint. The server refuses it; this is what stops the agent from asking.
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

	for _, source := range []Source{SourceSSO, SourceOIDC} {
		cred := &Material{
			CertPEM: []byte("unused: the refusal happens before anything is parsed"),
			Meta:    Meta{Identity: "jane@acme.com", Source: source},
		}
		if _, err := client.Renew(context.Background(), cred); !errors.Is(err, ErrNotRenewable) {
			t.Fatalf("Renew(%s) = %v, want ErrNotRenewable", source, err)
		}
	}
	if calls != 0 {
		t.Fatalf("the agent made %d request(s) to renew a sign-in or workload credential; it must make none", calls)
	}

	// A token credential the control plane gave no renew_after (its setup
	// token's renewal stop comes first) is refused the same way, so
	// `localport identity renew` sends nothing either.
	stopped := &Material{CertPEM: []byte("unused"), Meta: Meta{Identity: "deploy-prod", Kind: KindClient, Source: SourceToken}}
	if _, err := client.Renew(context.Background(), stopped); !errors.Is(err, ErrNotRenewable) || calls != 0 {
		t.Fatalf("Renew(token without renew_after) = %v after %d request(s), want ErrNotRenewable and none", err, calls)
	}

	// A token credential with a renewal time still renews.
	machine := &Material{Meta: Meta{Kind: KindClient, Source: SourceToken, RenewAfter: ptr(time.Now())}}
	if _, err := client.Renew(context.Background(), machine); errors.Is(err, ErrNotRenewable) {
		t.Fatal("a token credential must still renew")
	}
}

// A device flow credential has no renew_after.
func TestSignInMaterialCarriesNoRenewalDeadline(t *testing.T) {
	leaf := selfSigned(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/user/0mkppnsc7lsdcv")
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
	// The field is omitted. A zero time would serialize as year 1.
	if signIn.Meta.RenewAfter != nil {
		t.Fatalf("renew_after = %s, but the control plane sent none", *signIn.Meta.RenewAfter)
	}
	if _, renews := signIn.Meta.NextRenewal(); renews {
		t.Fatal("a sign-in must report that it does not renew, not a timestamp")
	}

}

// The control plane's renew_after decides whether a credential renews: a
// token credential without one does not, a workload credential never does,
// and a value that does not parse is a broken answer.
func TestRenewalTimeComesOnlyFromTheControlPlane(t *testing.T) {
	leaf := selfSigned(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/client/ci-runner")
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	client := &Client{BaseURL: "https://api.localport.io"}
	assemble := func(source Source, renewAfter string) (*Material, error) {
		return client.assemble(fileKey{testKey(t)}, issuedMaterial{CertPEM: certPEM, Source: source, RenewAfter: renewAfter})
	}

	for _, source := range []Source{SourceToken, SourceOIDC} {
		m, err := assemble(source, "")
		if err != nil {
			t.Fatalf("assemble(%s, absent): %v", source, err)
		}
		if _, renews := m.Meta.NextRenewal(); renews || m.Meta.RenewAfter != nil {
			t.Fatalf("a %s credential without renew_after renews at %v", source, m.Meta.RenewAfter)
		}
	}
	const at = "2026-12-01T10:00:00Z"
	m, err := assemble(SourceToken, at)
	if err != nil {
		t.Fatalf("assemble(token, %s): %v", at, err)
	}
	if due, renews := m.Meta.NextRenewal(); !renews || due.Format(time.RFC3339) != at {
		t.Fatalf("token renewal = %v %v, want %s", due, renews, at)
	}
	if m, err := assemble(SourceOIDC, at); err != nil || m.Meta.RenewAfter != nil {
		t.Fatalf("a workload credential stored renew_after %v (%v)", m.Meta.RenewAfter, err)
	}
	if _, err := assemble(SourceToken, "next tuesday"); !errors.Is(err, errcode.New(errcode.ControlPlaneAnswer)) {
		t.Fatalf("an unparsable renew_after = %v, want %s", err, errcode.ControlPlaneAnswer)
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

// Pins the device flow error codes shared with the control plane.
func TestLoginPollingIsDrivenByControlPlaneErrorCodes(t *testing.T) {
	if codeAuthorizationPending != "SE021" || codeSlowDown != "SE022" {
		t.Fatalf("polling codes drifted from the control plane: pending=%q slow_down=%q",
			codeAuthorizationPending, codeSlowDown)
	}

	// The server answers pending, slow_down, then the certificate. The loop
	// continues on the first two.
	leaf := selfSigned(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/user/0mkppnsc7lsdcv")
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))

	var polls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/mtls/device/start" {
			w.WriteHeader(http.StatusCreated)
			// Short interval to keep the test fast.
			fmt.Fprint(w, `{"device_code":"dc","user_code":"ABCD-EFGH","verification_uri":"https://127.0.0.1/device","verification_uri_complete":"https://127.0.0.1/device?code=ABCD-EFGH","interval":1,"expires_in":600}`)
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

	// Built directly to bypass the https check in NewClient.
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	// The poll floor is 5s, so the test sets its own deadline.
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
			fmt.Fprint(w, `{"device_code":"dc","user_code":"ABCD-EFGH","verification_uri":"https://127.0.0.1/device","verification_uri_complete":"https://127.0.0.1/device?code=ABCD-EFGH","interval":1,"expires_in":600}`)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"code":"VAL001","error":"Input Error","message":"That sign-in is no longer valid."}`)
	}))
	defer srv.Close()

	// Built directly to bypass the https check in NewClient.
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := client.Login(ctx, nil); err == nil {
		t.Fatal("expected an unrecognised refusal to end the loop")
	} else if !strings.Contains(err.Error(), "VAL001") {
		t.Fatalf("the support code must reach the operator, got %v", err)
	}
}

// credentialFor builds a self-signed leaf and key for Save and Load round trips.
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
		// Save validates Source.
		Meta: Meta{APIURL: "https://api.localport.io", Source: SourceToken},
	}
}

// Only one writer holds the renewal lock. Concurrent renewals would orphan
// certificates and exhaust the live certificate cap. flock is per open file
// description, so a second holder conflicts within one process.
func TestRenewalLockAdmitsOneWriter(t *testing.T) {
	store := &Store{Root: t.TempDir()}
	ref, err := store.Save(context.Background(), credentialFor(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/client/deploy-prod"))
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

// Without a home the unprivileged store has no root. A machine-wide fallback
// would collide with the privileged root, which differs only in case.
func TestDefaultRootRefusesWithoutAHome(t *testing.T) {
	t.Setenv(HomeEnv, "")
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	t.Setenv("home", "")

	if root, _, err := defaultRoot(); err == nil {
		t.Fatalf("defaultRoot with no home = %q, want an error naming %s", root, HomeEnv)
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

// A renewal proof signed through crypto.Signer verifies like ecdsa.SignASN1.
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

// Load reads what Save wrote through the names in meta.json.
func TestSaveRoundTripsTheKeyBacking(t *testing.T) {
	store := &Store{Root: t.TempDir()}
	ref, err := store.Save(context.Background(), credentialFor(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/client/deploy-prod"))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := readMeta(filepath.Join(store.Dir(ref), metaFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(store.Dir(ref), meta.Key.File)); err != nil {
		t.Fatalf("a file-backed key must be written: %v", err)
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

// meta.json never stores a zero time. It serializes as
// "0001-01-01T00:00:00Z" and would schedule renewal in the past.
func TestStoredMetadataNeverCarriesAZeroTimestamp(t *testing.T) {
	store := &Store{Root: t.TempDir()}
	cred := credentialFor(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/user/0mkppnsc7lsdcv")
	cred.Meta.Source = SourceSSO

	ref, err := store.Save(context.Background(), cred)
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
	// A sign-in has no renewal, so the field is omitted.
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

// A record json.Unmarshal accepts but that names an enum value this build does
// not know is refused when read, not at a later handshake.
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

// The server's message and code reach terminals and logs: control and bidi
// characters are dropped where the error response is decoded.
func TestAPIErrorDropsControlCharacters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"code":"SE011\n","message":"Renewal \u001b[2Jdenied`+"\xe2\x80\xae"+`\nerror: fake line"}`)
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	leaf := selfSigned(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/client/deploy-prod")
	cur := &Material{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		Key:     fileKey{testKey(t)},
		Meta:    Meta{Identity: "deploy-prod", Source: SourceToken, RenewAfter: ptr(time.Now())},
	}
	_, err := client.Renew(context.Background(), cur)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("Renew = %v, want an APIError", err)
	}
	if apiErr.Code != "SE011" || apiErr.Message != "Renewal [2Jdeniederror: fake line" {
		t.Fatalf("code %q, message %q; want control and bidi characters dropped", apiErr.Code, apiErr.Message)
	}
}

// A 403 on a device renew keeps the server code and names the new join
// command as the remedy.
func TestDeviceRenewRefusalNamesANewJoinCommand(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"code":"SE031","message":"device removed from the team"}`)
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	leaf := selfSigned(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/device/tun12345.gw-01")
	cur := &Material{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		Key:     fileKey{testKey(t)},
		Meta:    Meta{Identity: "tun12345.gw-01", Kind: KindDevice, Source: SourceToken},
	}
	_, err := client.Renew(context.Background(), cur)
	text, _ := errcode.Render(err)
	if !strings.Contains(text, errcode.NewJoinCommand) || !strings.Contains(text, "[SE031]") {
		t.Fatalf("Render = %q, want the server code and the join command remedy", text)
	}
}

// A 403 on renew keeps the APIError code and adds the `localport setup` hint.
func TestRenewRefusalSaysToRunSetupAgain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"code":"SE011","error":"Access Denied By Scope","message":"Renewal denied"}`)
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}

	leaf := selfSigned(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/client/deploy-prod")
	cur := &Material{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		Key:     fileKey{testKey(t)},
		Meta:    Meta{Identity: "deploy-prod", Source: SourceToken, RenewAfter: ptr(time.Now())},
	}
	_, err := client.Renew(context.Background(), cur)
	if err == nil {
		t.Fatal("a refused renewal returned no error")
	}
	if text, _ := errcode.Render(err); !strings.Contains(text, "localport setup") || !strings.Contains(text, "[SE011]") {
		t.Fatalf("Render = %q, want the server code and how to recover", text)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "SE011" {
		t.Fatalf("the server's code was lost: %v", err)
	}
}

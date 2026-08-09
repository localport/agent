package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

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

	// Overwrite in place with a different principal.
	other := credentialFor(t, "spiffe://team_x.mtls.localport.dev/client/other-box")
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

// Components are used VERBATIM, and a component that could escape the store is
// REFUSED rather than repaired.
//
// The Ref is built from a certificate, so `..` in an identity is the case that
// matters: repairing it would file the credential under a name that is not the
// one the certificate carries.
func TestRefRefusesComponentsThatEscapeTheStore(t *testing.T) {
	base := Ref{Team: "01kppnsc7lsdcv", Kind: KindClient, Identity: "deploy-prod"}
	if !base.valid() {
		t.Fatal("an ordinary ref must be valid")
	}
	if got := base.dir(); got != "01kppnsc7lsdcv/deploy-prod" {
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

// Only a key that says it is persistent leaves a key.pem behind, and Load must
// find whatever Save wrote.
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
		Meta:    Meta{APIURL: "https://api.localport.io", Source: SourceToken},
	}
}

package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func nowPlusHour() time.Time { return time.Now().Add(time.Hour) }

// Writing meta.json commits the serial-named certificate and key.
func TestSaveCommitsThroughMetaJSON(t *testing.T) {
	store := &Store{Root: t.TempDir()}

	first := credentialFor(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/client/deploy-prod")
	ref, err := store.Save(first)
	if err != nil {
		t.Fatal(err)
	}
	dir := store.Dir(ref)

	meta, err := readMeta(filepath.Join(dir, metaFile))
	if err != nil {
		t.Fatal(err)
	}
	if meta.Cert == "" || meta.Key.File == "" {
		t.Fatalf("meta names no pair: cert=%q key=%q", meta.Cert, meta.Key.File)
	}
	for _, name := range []string{meta.Cert, meta.Key.File} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s missing after Save: %v", name, err)
		}
	}

	// A second Save sweeps the previous pair and keeps the lock.
	if _, err := store.Save(credentialFor(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/client/deploy-prod")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, meta.Cert)); !os.IsNotExist(err) {
		t.Fatalf("previous certificate %s survived the sweep", meta.Cert)
	}
	if _, err := readMeta(filepath.Join(dir, metaFile)); err != nil {
		t.Fatalf("meta.json unusable after the sweep: %v", err)
	}
}

// If a crash leaves a new pair without meta.json, the previous credential
// still loads.
func TestInterruptedSaveLeavesThePreviousCredentialLoadable(t *testing.T) {
	store := &Store{Root: t.TempDir()}

	original := credentialFor(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/client/deploy-prod")
	ref, err := store.Save(original)
	if err != nil {
		t.Fatal(err)
	}
	dir := store.Dir(ref)
	committed, err := readMeta(filepath.Join(dir, metaFile))
	if err != nil {
		t.Fatal(err)
	}

	// A renewal that wrote its pair and crashed before the commit.
	next := credentialFor(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/client/deploy-prod")
	nextKey, err := next.Key.(persistentKey).marshal()
	if err != nil {
		t.Fatal(err)
	}
	orphanCert := filepath.Join(dir, "cert-deadbeef.pem")
	orphanKey := filepath.Join(dir, "key-deadbeef.pem")
	if err := os.WriteFile(orphanCert, next.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(orphanKey, nextKey, 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := store.Load(ref)
	if err != nil {
		t.Fatalf("the previous credential no longer loads: %v", err)
	}
	if loaded.Meta.Serial != committed.Serial {
		t.Fatalf("loaded serial %s, want the committed %s", loaded.Meta.Serial, committed.Serial)
	}
	if _, err := loaded.TLSCertificate(); err != nil {
		t.Fatalf("the previous credential is not usable: %v", err)
	}
}

// A key that does not match the certificate fails locally.
func TestTLSCertificateRefusesAMismatchedPair(t *testing.T) {
	store := &Store{Root: t.TempDir()}
	ref, err := store.Save(credentialFor(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/client/deploy-prod"))
	if err != nil {
		t.Fatal(err)
	}
	dir := store.Dir(ref)
	meta, err := readMeta(filepath.Join(dir, metaFile))
	if err != nil {
		t.Fatal(err)
	}

	// Another credential's key, under this one's key filename.
	other := credentialFor(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/client/other-machine")
	otherKey, err := other.Key.(persistentKey).marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, meta.Key.File), otherKey, 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := store.Load(ref)
	if err != nil {
		t.Fatal(err)
	}
	_, err = loaded.TLSCertificate()
	if err == nil {
		t.Fatal("a mismatched key and certificate must be refused")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error should name the mismatch, got %q", err)
	}
}

// The certificate and key file names are set together or not at all.
func TestMetaValidateRejectsAHalfNamedPair(t *testing.T) {
	base := func() Meta {
		return Meta{
			Identity: "deploy-prod", Team: "01kpq7x2abcd34", Kind: KindClient,
			Source: SourceToken, NotAfter: nowPlusHour(),
		}
	}
	m := base()
	m.Cert = "cert-1.pem"
	if err := m.validate(); err == nil {
		t.Error("a cert with no key must be refused")
	}
	m = base()
	m.Key.File = "key-1.pem"
	if err := m.validate(); err == nil {
		t.Error("a key with no cert must be refused")
	}
	m = base()
	m.Cert = "../escape.pem"
	m.Key.File = "key-1.pem"
	if err := m.validate(); err == nil {
		t.Error("a traversing filename must be refused")
	}
}

// Ref components match the server grammar of lowercase alphanumerics and
// internal dashes.
func TestRefValidMatchesTheServerIdentityGrammar(t *testing.T) {
	ok := []Ref{
		{Team: "01kpq7x2abcd34", Kind: KindClient, Identity: "gw-01"},
		{Team: "01kpq7x2abcd34", Kind: KindUser, Identity: "0mkppnsc7lsdcv"},
		{Team: "01kpq7x2abcd34", Kind: KindDevice, Identity: "plc-01-factory"},
	}
	for _, r := range ok {
		if !r.valid() {
			t.Errorf("%s should be valid", r)
		}
	}

	bad := []Ref{
		{Team: "", Kind: KindClient, Identity: "gw-01"},
		{Team: "..", Kind: KindClient, Identity: "gw-01"},
		{Team: ".", Kind: KindClient, Identity: "gw-01"},
		{Team: "01kpq7x2abcd34", Kind: KindClient, Identity: ".."},
		{Team: "a/b", Kind: KindClient, Identity: "gw-01"},
		{Team: `a\b`, Kind: KindClient, Identity: "gw-01"},
		{Team: "a:b", Kind: KindClient, Identity: "gw-01"},
		{Team: "team_x", Kind: KindClient, Identity: "gw-01"},         // underscore
		{Team: "01KPQ7X2ABCD34", Kind: KindClient, Identity: "gw-01"}, // uppercase
		{Team: "01kpq7x2abcd34", Kind: KindClient, Identity: "-gw"},   // leading dash
		{Team: "01kpq7x2abcd34", Kind: KindClient, Identity: "gw-"},   // trailing dash
		{Team: "01kpq7x2abcd34", Kind: "shell", Identity: "gw-01"},    // unknown kind
		{Team: "01kpq7x2abcd34", Kind: KindClient, Identity: strings.Repeat("a", 65)},
	}
	for _, r := range bad {
		if r.valid() {
			t.Errorf("%+v should be refused", r)
		}
	}
}

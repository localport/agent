package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A key that does not match the certificate fails locally.
func TestTLSCertificateRefusesAMismatchedPair(t *testing.T) {
	store := &Store{Root: t.TempDir()}
	ref, err := store.Save(credentialFor(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/client/deploy-prod"))
	if err != nil {
		t.Fatal(err)
	}
	dir := store.Dir(ref)

	// Another credential's key, under this one's key filename.
	other := credentialFor(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/client/other-machine")
	otherKey, err := other.Key.(persistentKey).marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, keyFile), otherKey, 0o600); err != nil {
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

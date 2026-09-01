package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/localport/agent/internal/identity"
)

func twoRefs() []identity.Ref {
	return []identity.Ref{
		{Team: "01kpq7x2", Kind: identity.KindClient, Identity: "gw-01"},
		{Team: "01kpq7x2", Kind: identity.KindUser, Identity: "7k2p9xq4mn3vb"},
	}
}

func TestChooseCredentialPicksTheNumberedRow(t *testing.T) {
	refs := twoRefs()
	var out bytes.Buffer
	got, err := chooseCredential(strings.NewReader("2\n"), &out, &identity.Store{Root: t.TempDir()}, refs)
	if err != nil {
		t.Fatalf("chooseCredential: %v", err)
	}
	if got != refs[1] {
		t.Fatalf("chose %v, want %v", got, refs[1])
	}
}

func TestChooseCredentialRepromptsOnBadInput(t *testing.T) {
	refs := twoRefs()
	var out bytes.Buffer
	// Not a number, then out of range, then valid.
	got, err := chooseCredential(strings.NewReader("x\n9\n1\n"), &out, &identity.Store{Root: t.TempDir()}, refs)
	if err != nil {
		t.Fatalf("chooseCredential: %v", err)
	}
	if got != refs[0] {
		t.Fatalf("chose %v, want %v", got, refs[0])
	}
	if n := strings.Count(out.String(), "Enter a number between"); n != 2 {
		t.Fatalf("re-prompted %d times, want 2", n)
	}
}

// EOF must abort. Defaulting to a credential nobody chose is how a process ends
// up presenting the wrong principal.
func TestChooseCredentialAbortsOnEOF(t *testing.T) {
	var out bytes.Buffer
	if _, err := chooseCredential(strings.NewReader(""), &out, &identity.Store{Root: t.TempDir()}, twoRefs()); err == nil {
		t.Fatal("EOF must abort rather than default to a credential")
	}
}

// The non-interactive answer has to be actionable: it prints the exact
// --identity value for each candidate, and those values must parse.
func TestAmbiguousErrorPrintsPastableSelectors(t *testing.T) {
	refs := twoRefs()
	msg := ambiguous(refs).Error()
	for _, r := range refs {
		want := "--identity " + r.String()
		if !strings.Contains(msg, want) {
			t.Fatalf("error does not offer %q:\n%s", want, msg)
		}
		sel, err := identity.ParseSelector(r.String())
		if err != nil {
			t.Fatalf("the value the error prints does not parse: %v", err)
		}
		if !sel.Matches(r) {
			t.Fatalf("the value the error prints does not select its own row")
		}
	}
}

// A selector that was SUPPLIED and matches nothing is an error, never a prompt.
// Otherwise a typo in LOCALPORT_IDENTITY opens a menu and a person picks a
// principal they never meant to present.
func TestSuppliedSelectorNeverPrompts(t *testing.T) {
	store := &identity.Store{Root: t.TempDir()}
	if _, err := resolveCredential(store, "01kpq7x2/nope", true); err == nil {
		t.Fatal("a supplied selector matching nothing must error")
	}
}

// With no credentials at all the message must point at the two commands that
// create one, not at the picker.
func TestNoCredentialsGivesTheSetupHint(t *testing.T) {
	store := &identity.Store{Root: t.TempDir()}
	_, err := resolveCredential(store, "", true)
	if err == nil {
		t.Fatal("want an error when the store is empty")
	}
	if !strings.Contains(err.Error(), "localport setup") {
		t.Fatalf("error should name `localport setup`, got: %v", err)
	}
}

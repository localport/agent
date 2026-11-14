package security

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/localport/agent/internal/errcode"
)

func TestResolveTokenFlagBeatsEnv(t *testing.T) {
	t.Setenv("LOCALPORT_TOKEN", "tok_env")
	tok, err := ResolveToken("tok_flag", "LOCALPORT_TOKEN")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if tok != "tok_flag" {
		t.Fatalf("tok = %q, want tok_flag", tok)
	}
}

func TestResolveTokenFallsBackToEnv(t *testing.T) {
	t.Setenv("LOCALPORT_TOKEN", "tok_env")
	tok, err := ResolveToken("", "LOCALPORT_TOKEN")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if tok != "tok_env" {
		t.Fatalf("tok = %q, want tok_env", tok)
	}
}

func TestUnreadableTokenFileIsCoded(t *testing.T) {
	t.Setenv("LOCALPORT_TOKEN", "")
	t.Setenv("LOCALPORT_TOKEN_FILE", t.TempDir()+"/missing")
	if _, err := ResolveToken("", "LOCALPORT_TOKEN"); !errors.Is(err, errcode.New(errcode.TokenFileUnreadable)) {
		t.Fatalf("ResolveToken = %v, want code %s", err, errcode.TokenFileUnreadable)
	}
}

func TestResolveTokenMissing(t *testing.T) {
	t.Setenv("LOCALPORT_TOKEN", "")
	if _, err := ResolveToken("", "LOCALPORT_TOKEN"); err == nil {
		t.Fatal("expected error for missing token")
	}
}

func TestRedactString(t *testing.T) {
	got := RedactString("token=abcdef stays here", "abcdef")
	if strings.Contains(got, "abcdef") {
		t.Fatalf("secret leaked: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("missing marker: %q", got)
	}
}

// The output layer masks every rendering and keeps the chain matchable.
func TestRedactErrorMasksTextAndKeepsTheChain(t *testing.T) {
	coded := errcode.New(errcode.CredentialNotKept)
	inner := coded.With(errors.New("server said tok_xyz"), "detail tok_xyz")
	err := fmt.Errorf("setup: %w", RedactError(inner, "tok_xyz"))

	rendered, _ := errcode.Render(err)
	for name, text := range map[string]string{
		"Error()": err.Error(),
		"%+v":     fmt.Sprintf("%+v", err),
		"Render":  rendered,
	} {
		if strings.Contains(text, "tok_xyz") || !strings.Contains(text, "[REDACTED]") {
			t.Errorf("%s = %q, want the secret redacted", name, text)
		}
	}
	if !errors.Is(err, coded) {
		t.Fatal("the coded error is no longer reachable through the wrapper")
	}
	if !strings.Contains(rendered, "["+string(errcode.CredentialNotKept)+"]") {
		t.Fatalf("Render = %q, want the code shown", rendered)
	}
}

// Bidi and zero-width characters are stripped (CVE-2021-42574). Code points are
// written as numbers so they are visible in this file.
func TestSanitizeDisplayStripsBidiAndInvisibleFormatting(t *testing.T) {
	strip := []struct {
		name string
		r    rune
	}{
		{"ZWSP", 0x200b},
		{"ZWNJ", 0x200c},
		{"LRM", 0x200e},
		{"RLM", 0x200f},
		{"LRE", 0x202a},
		{"PDF", 0x202c},
		{"RLO", 0x202e},
		{"word joiner", 0x2060},
		{"LRI", 0x2066},
		{"PDI", 0x2069},
		{"ZWNBSP", 0xfeff},
		{"ESC", 0x1b},
		{"DEL", 0x7f},
		{"C1 CSI", 0x9b},
	}
	for _, tc := range strip {
		in := "a" + string(tc.r) + "b"
		if got := SanitizeDisplay(in); got != "ab" {
			t.Errorf("%s (U+%04X): got %q, want %q", tc.name, tc.r, got, "ab")
		}
	}

	// Ordinary non-ASCII text is kept.
	keep := []string{
		"/api/v1/h" + string(rune(0xe9)) + "llo", // accented Latin
		"/" + string(rune(0x65e5)) + "/path",     // CJK
		"/" + string(rune(0x645)) + "rhb",        // Arabic letter
		"gw-01-factory",
		"/a b/c?d=1&e=2",
	}
	for _, in := range keep {
		if got := SanitizeDisplay(in); got != in {
			t.Errorf("SanitizeDisplay(%q) = %q, want it unchanged", in, got)
		}
	}
}

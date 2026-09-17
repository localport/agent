package security

import (
	"errors"
	"strings"
	"testing"
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

func TestSanitizeError(t *testing.T) {
	err := SanitizeError(errors.New("oops tok_xyz happened"), "tok_xyz")
	if err == nil || strings.Contains(err.Error(), "tok_xyz") {
		t.Fatalf("not redacted: %v", err)
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

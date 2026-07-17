package security

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
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

func TestValidatePrivateKeyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not enforced on Windows")
	}
	path := filepath.Join(t.TempDir(), "client.key")
	if err := os.WriteFile(path, []byte("test"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := ValidatePrivateKeyPermissions(path); err == nil {
		t.Fatal("expected reject for 0644")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := ValidatePrivateKeyPermissions(path); err != nil {
		t.Fatalf("0600 must pass: %v", err)
	}
}

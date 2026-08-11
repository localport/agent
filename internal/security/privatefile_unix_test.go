//go:build !windows

package security

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWritePrivateFileAtomicIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := WritePrivateFileAtomic(path, []byte("material")); err != nil {
		t.Fatalf("WritePrivateFileAtomic: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("mode %#o is readable by group or other", perm)
	}
	got, err := ReadPrivateFile(path)
	if err != nil {
		t.Fatalf("ReadPrivateFile: %v", err)
	}
	if string(got) != "material" {
		t.Fatalf("round trip returned %q", got)
	}
}

func TestWritePrivateFileAtomicReplacesAStaleTemporary(t *testing.T) {
	// An interrupted write leaves a temporary behind. The next write must not
	// fail on it, and must not adopt whatever mode it carried.
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path+".tmp", []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateFileAtomic(path, []byte("fresh")); err != nil {
		t.Fatalf("WritePrivateFileAtomic: %v", err)
	}
	got, err := ReadPrivateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "fresh" {
		t.Fatalf("read %q, want fresh", got)
	}
}

func TestOpenPrivateFileRefusesAKeyOthersCanRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte("material"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPrivateFile(path); err == nil {
		t.Fatal("expected 0644 to be refused")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := OpenPrivateFile(path)
	if err != nil {
		t.Fatalf("0600 must be accepted: %v", err)
	}
	f.Close()
}

// A symlink in place of the key would have us read whatever it points at, and
// report the link's own permissions rather than the target's.
func TestOpenPrivateFileRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.pem")
	if err := os.WriteFile(target, []byte("material"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "key.pem")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := OpenPrivateFile(link); err == nil {
		t.Fatal("expected a symlinked key to be refused")
	}
}

// Correct permissions on the final directory mean nothing if a parent redirects
// it. Whoever plants the link chooses where the key is written.
func TestEnsurePrivateDirRefusesASymlinkedParent(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := EnsurePrivateDir(root, filepath.Join(link, "team", "client-deploy")); err == nil {
		t.Fatal("expected a path through a symlinked parent to be refused")
	}
}

func TestEnsurePrivateDirTightensAnExistingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "identity")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDir(filepath.Dir(dir), dir); err != nil {
		t.Fatalf("EnsurePrivateDir: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("mode %#o left readable by group or other", perm)
	}
}

// LoadCredential= and docker secrets both deliver a token as a file rather than
// an environment variable, which keeps it out of /proc/<pid>/environ.
func TestResolveOptionalTokenReadsTheFileForm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := WritePrivateFileAtomic(path, []byte("tok_from_file\n")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LP_TEST_TOKEN_FILE", path)

	got, err := ResolveOptionalToken("", "LP_TEST_TOKEN")
	if err != nil {
		t.Fatalf("ResolveOptionalToken: %v", err)
	}
	if got != "tok_from_file" {
		t.Fatalf("token = %q, want tok_from_file (trailing newline must be trimmed)", got)
	}

	// An explicitly set value wins, matching the services' *_FILE precedence.
	t.Setenv("LP_TEST_TOKEN", "tok_from_env")
	if got, err = ResolveOptionalToken("", "LP_TEST_TOKEN"); err != nil || got != "tok_from_env" {
		t.Fatalf("ResolveOptionalToken = %q, %v; want tok_from_env", got, err)
	}
	// And the flag wins over both.
	if got, err = ResolveOptionalToken("tok_from_flag", "LP_TEST_TOKEN"); err != nil || got != "tok_from_flag" {
		t.Fatalf("ResolveOptionalToken = %q, %v; want tok_from_flag", got, err)
	}
}

func TestResolveOptionalTokenRefusesAWorldReadableTokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("tok_exposed"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LP_TEST_TOKEN_FILE", path)
	if _, err := ResolveOptionalToken("", "LP_TEST_TOKEN"); err == nil {
		t.Fatal("expected a 0644 token file to be refused")
	}
}

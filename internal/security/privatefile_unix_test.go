//go:build !windows

package security

import (
	"errors"
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
	if err := EnsurePrivateDir(root, filepath.Join(link, "team", "client-deploy"), true); err == nil {
		t.Fatal("expected a path through a symlinked parent to be refused")
	}
}

func TestEnsurePrivateDirTightensAnExistingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "identity")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDir(filepath.Dir(dir), dir, true); err != nil {
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

// A symlink component is refused before any mkdir or chmod reaches its
// target.
func TestEnsurePrivateDirRefusesSymlinkComponent(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.Mkdir(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(root, "identity")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	err := EnsurePrivateDir(root, filepath.Join(root, "identity"), true)
	if !errors.Is(err, ErrUntrustedPath) {
		t.Fatalf("err = %v, want ErrUntrustedPath", err)
	}
	info, statErr := os.Stat(victim)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("the link's target was chmod-ed to %#o", got)
	}
	if entries, _ := os.ReadDir(victim); len(entries) != 0 {
		t.Fatalf("something was created inside the link's target: %v", entries)
	}
}

// A regular file in place of a directory component is refused.
func TestEnsurePrivateDirRefusesAFileComponent(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "identity"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDir(root, filepath.Join(root, "identity", "team"), true); !errors.Is(err, ErrUntrustedPath) {
		t.Fatalf("err = %v, want ErrUntrustedPath", err)
	}
}

func TestEnsurePrivateDirCreatesMissing0700(t *testing.T) {
	root := filepath.Join(t.TempDir(), "home")
	dir := filepath.Join(root, "identity", "team", "client-deploy")
	if err := EnsurePrivateDir(root, dir, true); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, filepath.Join(root, "identity"), filepath.Join(root, "identity", "team"), dir} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Errorf("%s: mode %v, want a 0700 directory", path, info.Mode())
		}
	}
}

// With followRoot a symlinked root is accepted when its target is ours.
func TestEnsurePrivateDirAllowsASymlinkedRoot(t *testing.T) {
	real := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "home")
	if err := os.Symlink(real, root); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := EnsurePrivateDir(root, filepath.Join(root, "identity"), true); err != nil {
		t.Fatalf("a symlinked root was refused: %v", err)
	}
}

// A component owned by another uid is refused. Needs root for chown.
func TestEnsurePrivateDirRefusesForeignOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a directory owned by another account")
	}
	root := t.TempDir()
	foreign := filepath.Join(root, "identity")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(foreign, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDir(root, filepath.Join(foreign, "team"), true); !errors.Is(err, ErrUntrustedPath) {
		t.Fatalf("err = %v, want ErrUntrustedPath", err)
	}
}

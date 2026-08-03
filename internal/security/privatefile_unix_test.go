//go:build !windows

package security

import (
	"os"
	"path/filepath"
	"testing"
)

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

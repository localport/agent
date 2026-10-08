//go:build windows

package security

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// junction creates a directory junction at link. It needs only write access to
// the parent.
func junction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("cannot create a junction: %v: %s", err, out)
	}
}

func TestEnsurePrivateDirCreatesAndAcceptsItsOwnTree(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	dir := filepath.Join(root, "team", "client-deploy")
	if err := EnsurePrivateDir(root, dir, true); err != nil {
		t.Fatalf("EnsurePrivateDir: %v", err)
	}
	if err := CheckPrivateDir(root, dir, true); err != nil {
		t.Fatalf("CheckPrivateDir on a tree just created: %v", err)
	}
}

// A junction below root is refused by both walks and nothing is created behind
// it.
func TestPrivateDirRefusesAJunction(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "store")
	if err := EnsurePrivateDir(root, root, true); err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(base, "elsewhere")
	if err := os.Mkdir(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	junction(t, filepath.Join(root, "team"), elsewhere)

	dir := filepath.Join(root, "team", "client-deploy")
	if err := EnsurePrivateDir(root, dir, true); !errors.Is(err, ErrUntrustedPath) {
		t.Fatalf("EnsurePrivateDir through a junction: err = %v, want ErrUntrustedPath", err)
	}
	if err := CheckPrivateDir(root, filepath.Join(root, "team"), true); !errors.Is(err, ErrUntrustedPath) {
		t.Fatalf("CheckPrivateDir on a junction: err = %v, want ErrUntrustedPath", err)
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatalf("something was created behind the junction: %v", entries)
	}
}

// OpenLockFile refuses a junction or directory and reopens a regular file.
func TestOpenLockFile(t *testing.T) {
	dir := t.TempDir()

	lock := filepath.Join(dir, "renew.lock")
	for range 2 {
		f, err := OpenLockFile(lock)
		if err != nil {
			t.Fatalf("OpenLockFile: %v", err)
		}
		_ = f.Close()
	}

	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(dir, "planted.lock")
	junction(t, planted, target)
	if f, err := OpenLockFile(planted); !errors.Is(err, ErrUntrustedPath) {
		if f != nil {
			_ = f.Close()
		}
		t.Fatalf("OpenLockFile on a junction: err = %v, want ErrUntrustedPath", err)
	}

	// a directory at the lock path is refused too.
	if f, err := OpenLockFile(target); !errors.Is(err, ErrUntrustedPath) {
		if f != nil {
			_ = f.Close()
		}
		t.Fatalf("OpenLockFile on a directory: err = %v, want ErrUntrustedPath", err)
	}
}

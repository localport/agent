//go:build windows

package security

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
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

// Securing a directory that already holds files and directories leaves them
// readable by this account and grants nobody else write on them: the
// protected DACL's entries are inherited, so the propagation SetSecurityInfo
// runs replaces the children's inherited entries rather than emptying them.
func TestEnsurePrivateDirKeepsExistingChildrenReachable(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	files := []string{filepath.Join(root, "child.txt"), filepath.Join(sub, "nested.txt")}
	for _, f := range files {
		if err := os.WriteFile(f, []byte("kept"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := EnsurePrivateDir(root, root, true); err != nil {
		t.Fatalf("EnsurePrivateDir: %v", err)
	}
	for _, f := range files {
		if got, err := os.ReadFile(f); err != nil || string(got) != "kept" {
			t.Fatalf("read %s after securing its parent = %q, %v", f, got, err)
		}
	}
	for _, p := range append([]string{sub}, files...) {
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := assertNoForeignWriter(dacl, p); err != nil {
			t.Fatalf("%s after securing its parent: %v", p, err)
		}
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

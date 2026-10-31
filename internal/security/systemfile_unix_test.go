//go:build !windows

package security

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// asSystemOwner makes the test's own uid the required system owner.
func asSystemOwner(t *testing.T) {
	t.Helper()
	t.Cleanup(OverrideSystemOwner(os.Getuid()))
}

// asForeignOwner requires an owner the test's files never have.
func asForeignOwner(t *testing.T) {
	t.Helper()
	t.Cleanup(OverrideSystemOwner(os.Getuid() + 1))
}

func wantUntrusted(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrUntrustedPath) {
		t.Fatalf("err = %v, want ErrUntrustedPath", err)
	}
}

func TestEnsureSystemDirCreatesRootGroupDir(t *testing.T) {
	asSystemOwner(t)
	dir := filepath.Join(t.TempDir(), "device")
	if err := EnsureSystemDir(dir, os.Getgid()); err != nil {
		t.Fatalf("EnsureSystemDir: %v", err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := EnsureSystemDir(dir, os.Getgid()); err != nil {
		t.Fatalf("EnsureSystemDir on existing: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o750 {
		t.Fatalf("mode %#o, want 0750", perm)
	}
	if err := CheckSystemDir(dir); err != nil {
		t.Fatalf("CheckSystemDir: %v", err)
	}
}

func TestEnsureSystemDirRefusesForeignOwner(t *testing.T) {
	dir := t.TempDir()
	asForeignOwner(t)
	wantUntrusted(t, EnsureSystemDir(dir, os.Getgid()))
}

func TestSystemDirRefusesSymlink(t *testing.T) {
	asSystemOwner(t)
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	wantUntrusted(t, CheckSystemDir(link))
	wantUntrusted(t, EnsureSystemDir(link, os.Getgid()))
}

func TestCheckSystemDirRefusals(t *testing.T) {
	asSystemOwner(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	wantUntrusted(t, CheckSystemDir(dir))
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	asForeignOwner(t)
	wantUntrusted(t, CheckSystemDir(dir))
}

func TestWriteAndReadSystemFile(t *testing.T) {
	asSystemOwner(t)
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := WriteSystemFileAtomic(path, []byte("cfg"), os.Getgid()); err != nil {
		t.Fatalf("WriteSystemFileAtomic: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o640 {
		t.Fatalf("mode %#o, want 0640", perm)
	}
	if gid := info.Sys().(*syscall.Stat_t).Gid; int(gid) != os.Getgid() {
		t.Fatalf("gid %d, want %d", gid, os.Getgid())
	}
	got, err := ReadSystemFile(path)
	if err != nil || string(got) != "cfg" {
		t.Fatalf("ReadSystemFile = %q, %v", got, err)
	}
}

func TestReadSystemFileRefusals(t *testing.T) {
	asSystemOwner(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(path, []byte("cfg"), 0o640); err != nil {
		t.Fatal(err)
	}
	for _, perm := range []os.FileMode{0o660, 0o644, 0o642} {
		if err := os.Chmod(path, perm); err != nil {
			t.Fatal(err)
		}
		_, err := ReadSystemFile(path)
		wantUntrusted(t, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	_, err := ReadSystemFile(link)
	wantUntrusted(t, err)
	_, err = ReadSystemFile(dir)
	wantUntrusted(t, err)
	asForeignOwner(t)
	_, err = ReadSystemFile(path)
	wantUntrusted(t, err)
}

func TestOpenSystemLockSetsMode(t *testing.T) {
	asSystemOwner(t)
	path := filepath.Join(t.TempDir(), "run.lock")
	f, err := OpenSystemLock(path, os.Getgid(), SystemRunLockPerm)
	if err != nil {
		t.Fatalf("OpenSystemLock: %v", err)
	}
	f.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o660 {
		t.Fatalf("mode %#o, want 0660", perm)
	}
	f, err = OpenSystemRunLock(path)
	if err != nil {
		t.Fatalf("OpenSystemRunLock: %v", err)
	}
	f.Close()
}

func TestSystemLockRefusesSymlink(t *testing.T) {
	asSystemOwner(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o660); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "run.lock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenSystemLock(link, os.Getgid(), SystemRunLockPerm); err == nil {
		f.Close()
		t.Fatal("OpenSystemLock followed a symlink")
	}
	if f, err := OpenSystemRunLock(link); err == nil {
		f.Close()
		t.Fatal("OpenSystemRunLock followed a symlink")
	}
}

func TestOpenSystemRunLockRefusals(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "run.lock")
	if _, err := OpenSystemRunLock(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing lock: err = %v, want ErrNotExist", err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("OpenSystemRunLock created the lock")
	}
	if err := os.WriteFile(missing, nil, 0o660); err != nil {
		t.Fatal(err)
	}
	asForeignOwner(t)
	_, err := OpenSystemRunLock(missing)
	wantUntrusted(t, err)
}

//go:build unix

package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// A user config whose home is a symlink (LOCALPORT_HOME or a linked
// ~/.localport) is followed as EnsurePrivateDir follows it: LockRun locks the
// linked directory, a second LockRun is refused, and a child adopts the lock.
func TestLockRunFollowsALinkedUserHome(t *testing.T) {
	tmp := t.TempDir()
	real := filepath.Join(tmp, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(tmp, "home")
	if err := os.Symlink(real, home); err != nil {
		t.Fatal(err)
	}
	f := LocalConfigFile{Path: filepath.Join(home, "agent.yaml"), Base: home, FollowBase: true}
	lock, release, err := LockRunFile(context.Background(), f, 0)
	if err != nil {
		t.Fatalf("LockRunFile through a linked home = %v", err)
	}
	defer func() { _ = release() }()
	if second, err := LockRun(f, 0); !errors.Is(err, ErrRunLocked) {
		if err == nil {
			_ = second()
		}
		t.Fatalf("second LockRun = %v, want ErrRunLocked", err)
	}
	if err := AdoptRunLock(f, lock); err != nil {
		t.Fatalf("AdoptRunLock through a linked home = %v", err)
	}
}

// The descriptors LockRun holds, the locked config directory and the
// run.lock record, are close-on-exec, so a child process (a session shell)
// never inherits the run lock.
func TestLockRunIsCloseOnExec(t *testing.T) {
	f := testRunFile(t)
	release, err := LockRun(f, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = release() }()
	for _, path := range []string{filepath.Dir(f.Path), f.RunLockPath()} {
		var want unix.Stat_t
		if err := unix.Stat(path, &want); err != nil {
			t.Fatal(err)
		}
		found := false
		for fd := 3; fd < 1024; fd++ {
			var st unix.Stat_t
			if unix.Fstat(fd, &st) != nil || st.Dev != want.Dev || st.Ino != want.Ino {
				continue
			}
			found = true
			flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
			if err != nil {
				t.Fatal(err)
			}
			if flags&unix.FD_CLOEXEC == 0 {
				t.Fatalf("descriptor %d of %s is inherited by child processes", fd, path)
			}
		}
		if !found {
			t.Fatalf("no open descriptor for %s", path)
		}
	}
}

// A child adopts the run.lock its parent holds through a duplicate
// descriptor; it refuses another file, and a run.lock another holder has.
func TestAdoptRunLock(t *testing.T) {
	f := testRunFile(t)
	lock, release, err := LockRunFile(context.Background(), f, 0)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Dup(int(lock.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	passed := os.NewFile(uintptr(fd), "run.lock")
	if err := AdoptRunLock(f, passed); err != nil {
		t.Fatalf("adopt the parent's run.lock: %v", err)
	}
	// The child's exit (its close) leaves the parent's lock held.
	_ = passed.Close()
	if _, err := LockRun(f, 0); !errors.Is(err, ErrRunLocked) {
		t.Fatalf("after the child closed its copy: %v, want ErrRunLocked", err)
	}

	other, err := os.OpenFile(f.Path+".other", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := AdoptRunLock(f, other); err == nil || errors.Is(err, ErrRunLocked) {
		t.Fatalf("adopt another file: %v, want a refusal", err)
	}

	// run.lock only records the holder: its descriptor is not the run lock.
	record, err := os.OpenFile(f.RunLockPath(), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer record.Close()
	if err := AdoptRunLock(f, record); err == nil || errors.Is(err, ErrRunLocked) {
		t.Fatalf("adopt the run.lock record file: %v, want a refusal", err)
	}

	// A fresh description of the locked directory does not hold the parent's
	// lock.
	fresh, err := os.Open(filepath.Dir(f.Path))
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err := AdoptRunLock(f, fresh); !errors.Is(err, ErrRunLocked) {
		t.Fatalf("adopt a run lock another process holds: %v, want ErrRunLocked", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

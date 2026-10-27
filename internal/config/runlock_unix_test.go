//go:build unix

package config

import (
	"testing"

	"golang.org/x/sys/unix"
)

// The descriptor LockRun holds is close-on-exec, so a child process (a
// session shell) never inherits run.lock.
func TestLockRunIsCloseOnExec(t *testing.T) {
	f := testRunFile(t)
	release, err := LockRun(f, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = release() }()
	var want unix.Stat_t
	if err := unix.Stat(f.RunLockPath(), &want); err != nil {
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
			t.Fatalf("run.lock descriptor %d is inherited by child processes", fd)
		}
	}
	if !found {
		t.Fatal("no open descriptor for run.lock")
	}
}

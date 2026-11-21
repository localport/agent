//go:build linux || darwin

package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/localport/agent/internal/childproc"
)

// fakeWatch is an exit watch whose registration or wait fails on demand. It
// records the pid it was given.
type fakeWatch struct {
	watchErr, waitErr error
	pid               int
}

func (w *fakeWatch) Watch(pid int) error { w.pid = pid; return w.watchErr }
func (w *fakeWatch) Wait() error         { return w.waitErr }
func (w *fakeWatch) Close() error        { return nil }

func setExitWatch(t *testing.T, newWatch func() (childproc.Watcher, error)) {
	t.Helper()
	old := newExitWatch
	newExitWatch = newWatch
	t.Cleanup(func() { newExitWatch = old })
}

// countGroupSignals counts the signals sent to a process group by number.
func countGroupSignals(t *testing.T) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	old := killGroup
	killGroup = func(pid int, s syscall.Signal) error { n.Add(1); return old(pid, s) }
	t.Cleanup(func() { killGroup = old })
	return &n
}

// Without an exit watch the child is not spawned.
func TestRunRelayedRefusedWithoutAnExitWatch(t *testing.T) {
	setExitWatch(t, func() (childproc.Watcher, error) { return nil, unix.EMFILE })
	marker := filepath.Join(t.TempDir(), "ran")
	err := runRelayed(exec.Command("/bin/sh", "-c", "touch "+marker), bytes.NewReader(nil), io.Discard, io.Discard, false)
	if err == nil {
		t.Fatal("the child started")
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the child ran: %v", err)
	}
}

// A child whose exit cannot be registered is killed and reaped; the run fails.
func TestRunRelayedRefusedWhenTheWatchFails(t *testing.T) {
	w := &fakeWatch{watchErr: unix.ENOMEM}
	setExitWatch(t, func() (childproc.Watcher, error) { return w, nil })
	if err := runRelayed(exec.Command("/bin/sh", "-c", "sleep 30"), bytes.NewReader(nil), io.Discard, io.Discard, false); err == nil {
		t.Fatal("the child started")
	}
	if w.pid == 0 {
		t.Fatal("the watch was never registered")
	}
	if err := syscall.Kill(w.pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("child %d after the refused start: %v", w.pid, err)
	}
}

// A signal root receives goes to the child's group while the exit is
// observable, and only to the child once it is not.
func TestRunRelayedSignalsOnlyTheChildWhenTheExitIsUnobservable(t *testing.T) {
	for _, tc := range []struct {
		name       string
		unobserved bool
	}{{"observable", false}, {"unobservable", true}} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.unobserved {
				setExitWatch(t, func() (childproc.Watcher, error) { return &fakeWatch{waitErr: unix.EBADF}, nil })
			}
			groups := countGroupSignals(t)
			ready := filepath.Join(t.TempDir(), "ready")
			cmd := exec.Command("/bin/sh", "-c", "touch "+ready+"; while :; do sleep 0.1; done")
			done := runRelayedAsync(cmd, bytes.NewReader(nil), io.Discard, io.Discard, false)
			deadline := time.Now().Add(10 * time.Second)
			for _, err := os.Stat(ready); err != nil; _, err = os.Stat(ready) {
				if time.Now().After(deadline) {
					t.Fatal("the child never started")
				}
				time.Sleep(10 * time.Millisecond)
			}
			// runWithSignals relays root's SIGTERM to the child.
			if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("runRelayed did not return after SIGTERM")
			}
			if got, want := groups.Load() > 0, !tc.unobserved; got != want {
				t.Fatalf("group signalled %v; want %v", got, want)
			}
		})
	}
}

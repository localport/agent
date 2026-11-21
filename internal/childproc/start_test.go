//go:build linux || darwin

package childproc

import (
	"errors"
	"os/exec"
	"syscall"
	"testing"
)

// failingWatch refuses registration and records what StartWatched did with it.
type failingWatch struct {
	pid    int
	closed bool
}

func (w *failingWatch) Watch(pid int) error { w.pid = pid; return syscall.EMFILE }
func (w *failingWatch) Wait() error         { return nil }
func (w *failingWatch) Close() error        { w.closed = true; return nil }

// A registration failure kills the child's group, reaps the child, closes
// the watch and fails the start.
func TestStartWatchedCleansUpWhenTheWatchFails(t *testing.T) {
	w := &failingWatch{}
	var killed []syscall.Signal
	kill := func(pid int, s syscall.Signal) error {
		killed = append(killed, s)
		return syscall.Kill(-pid, s)
	}
	cmd := exec.Command("sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	got, err := StartWatched(cmd, func() (Watcher, error) { return w, nil }, (*exec.Cmd).Start, kill)
	if !errors.Is(err, syscall.EMFILE) || got != nil {
		t.Fatalf("StartWatched = %v, %v; want nil and EMFILE", got, err)
	}
	if w.pid != cmd.Process.Pid {
		t.Fatalf("watched pid %d, child %d", w.pid, cmd.Process.Pid)
	}
	if len(killed) != 1 || killed[0] != syscall.SIGKILL {
		t.Fatalf("group signals %v, want one SIGKILL", killed)
	}
	if cmd.ProcessState == nil {
		t.Fatal("the child was not reaped")
	}
	if !w.closed {
		t.Fatal("the watch was not closed")
	}
}

// A watch that cannot be created stops the start before the spawn, and a
// failed spawn closes the watch.
func TestStartWatchedRefusesWithoutAWatch(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	noWatch := func() (Watcher, error) { return nil, syscall.EMFILE }
	if _, err := StartWatched(cmd, noWatch, (*exec.Cmd).Start, nil); !errors.Is(err, syscall.EMFILE) {
		t.Fatalf("err %v, want EMFILE", err)
	}
	if cmd.Process != nil {
		t.Fatal("the child was spawned without a watch")
	}

	w := &failingWatch{}
	spawnErr := errors.New("spawn refused")
	_, err := StartWatched(exec.Command("sleep", "30"), func() (Watcher, error) { return w, nil },
		func(*exec.Cmd) error { return spawnErr }, nil)
	if !errors.Is(err, spawnErr) || !w.closed {
		t.Fatalf("err %v, closed %v; want the spawn error and a closed watch", err, w.closed)
	}
}

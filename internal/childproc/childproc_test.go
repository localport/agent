//go:build linux || darwin

package childproc

import (
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// waitWithin runs w.Wait and fails the test when it does not return within d.
func waitWithin(t *testing.T, w *ExitWatch, d time.Duration) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- w.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Wait: %v", err)
		}
	case <-time.After(d):
		t.Fatal("Wait did not return")
	}
}

// The watch reports the exit of a child that runs past its registration and
// leaves it unreaped.
func TestExitWatchObservesTheExit(t *testing.T) {
	w, err := NewExitWatch()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	cmd := exec.Command("/bin/sh", "-c", "sleep 0.3; exit 5")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := w.Watch(cmd.Process.Pid); err != nil {
		t.Fatal(err)
	}
	waitWithin(t, w, 10*time.Second)
	// Unreaped: the pid still names the zombie.
	if err := syscall.Kill(cmd.Process.Pid, 0); err != nil {
		t.Fatalf("child reaped by the watch: %v", err)
	}
	if err := cmd.Wait(); cmd.ProcessState.ExitCode() != 5 {
		t.Fatalf("exit %v; want status 5", err)
	}
}

// A child that exited, unreaped, before its registration is reported at once.
func TestExitWatchOfAnExitedChild(t *testing.T) {
	w, err := NewExitWatch()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Wait() }()
	time.Sleep(300 * time.Millisecond)
	if err := w.Watch(cmd.Process.Pid); err != nil {
		t.Fatal(err)
	}
	waitWithin(t, w, time.Second)
}

//go:build linux || darwin

package childproc

import (
	"fmt"
	"os/exec"
	"syscall"
)

// Watcher observes one child's exit without reaping it. *ExitWatch
// implements it; tests substitute their own.
type Watcher interface {
	Watch(pid int) error
	Wait() error
	Close() error
}

// NewWatcher is NewExitWatch as a Watcher: nil, not a typed nil, on error.
func NewWatcher() (Watcher, error) {
	w, err := NewExitWatch()
	if err != nil {
		return nil, err
	}
	return w, nil
}

// StartWatched starts cmd as a process group leader (Setsid) with its exit
// watch created before the spawn and registered right after. When the
// registration fails, the child's group gets SIGKILL, the child is reaped
// and the watch closed. On error nothing is left running.
func StartWatched(
	cmd *exec.Cmd,
	newWatch func() (Watcher, error),
	start func(*exec.Cmd) error,
	killGroup func(pid int, s syscall.Signal) error,
) (Watcher, error) {
	w, err := newWatch()
	if err != nil {
		return nil, fmt.Errorf("create the exit watch: %w", err)
	}
	if err := start(cmd); err != nil {
		_ = w.Close()
		return nil, err
	}
	if err := w.Watch(cmd.Process.Pid); err != nil {
		_ = killGroup(cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
		_ = w.Close()
		return nil, fmt.Errorf("watch the exit of %d: %w", cmd.Process.Pid, err)
	}
	return w, nil
}

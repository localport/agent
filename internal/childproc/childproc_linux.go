package childproc

import (
	"errors"

	"golang.org/x/sys/unix"
)

// ExitWatch observes one child's exit without reaping it (waitid WNOWAIT).
// It holds no descriptor.
type ExitWatch struct{ pid int }

// NewExitWatch returns a watch. Call it before spawning the child, as on
// macOS, where it allocates.
func NewExitWatch() (*ExitWatch, error) { return &ExitWatch{}, nil }

// Watch records the child pid, right after it started.
func (w *ExitWatch) Watch(pid int) error {
	w.pid = pid
	return nil
}

// Wait blocks until the watched child exited and leaves it unreaped.
func (w *ExitWatch) Wait() error {
	for {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, w.pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

// Close does nothing on Linux.
func (w *ExitWatch) Close() error { return nil }

// RevokeTTY does nothing on Linux: a PTY master is pollable, so its Close
// interrupts a blocked Read or Write.
func RevokeTTY(string) error { return nil }

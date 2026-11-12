package childproc

import (
	"errors"

	"golang.org/x/sys/unix"
)

// WaitExited blocks until the child pid exited and leaves it unreaped
// (waitid WNOWAIT).
func WaitExited(pid int) error {
	for {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

// RevokeTTY does nothing on Linux: a PTY master is pollable, so its Close
// interrupts a blocked Read or Write.
func RevokeTTY(string) error { return nil }

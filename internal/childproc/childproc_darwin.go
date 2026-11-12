package childproc

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

// WaitExited blocks until the child pid exited and leaves it unreaped. x/sys
// has no waitid on macOS; a kqueue EVFILT_PROC NOTE_EXIT filter observes the
// exit without reaping. ESRCH at registration means the unreaped child
// already exited.
func WaitExited(pid int) error {
	kq, err := unix.Kqueue()
	if err != nil {
		return err
	}
	defer unix.Close(kq)
	for {
		change := []unix.Kevent_t{{Ident: uint64(pid), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT}}
		events := make([]unix.Kevent_t, 1)
		n, err := unix.Kevent(kq, change, events, nil)
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case err != nil:
			return err
		case n == 0:
			continue
		case events[0].Flags&unix.EV_ERROR != 0:
			if errno := syscall.Errno(events[0].Data); errno != unix.ESRCH {
				return errno
			}
			return nil
		case events[0].Fflags&unix.NOTE_EXIT != 0:
			return nil
		}
	}
}

// RevokeTTY revokes every open of the PTY slave at path. A macOS master is
// a blocking file whose Close does not interrupt a blocked Read or Write;
// the revoke ends both, also while a process outside the session still
// holds the slave. The caller must own the slave or be root.
func RevokeTTY(path string) error { return unix.Revoke(path) }

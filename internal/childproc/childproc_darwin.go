package childproc

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

// ExitWatch observes one child's exit without reaping it. x/sys has no
// waitid on macOS; a kqueue EVFILT_PROC NOTE_EXIT filter observes the exit.
// The kqueue is created before the child is spawned, so a started child is
// never left without a watch for want of a descriptor.
type ExitWatch struct {
	kq int
	// exited is set when registration found the unreaped child already gone (ESRCH).
	exited bool
}

// NewExitWatch creates the watch's kqueue. Call it before spawning the child.
func NewExitWatch() (*ExitWatch, error) {
	kq, err := unix.Kqueue()
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(kq)
	return &ExitWatch{kq: kq}, nil
}

// Watch registers the child pid, right after it started and before it is
// reaped. ESRCH means the unreaped child already exited.
func (w *ExitWatch) Watch(pid int) error {
	change := []unix.Kevent_t{{Ident: uint64(pid), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT}}
	for {
		_, err := unix.Kevent(w.kq, change, nil, nil)
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.ESRCH):
			w.exited = true
			return nil
		default:
			return err
		}
	}
}

// Wait blocks until the watched child exited and leaves it unreaped.
func (w *ExitWatch) Wait() error {
	if w.exited {
		return nil
	}
	events := make([]unix.Kevent_t, 1)
	for {
		n, err := unix.Kevent(w.kq, nil, events, nil)
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

// Close releases the kqueue.
func (w *ExitWatch) Close() error { return unix.Close(w.kq) }

// RevokeTTY revokes every open of the PTY slave at path. A macOS master is
// a blocking file whose Close does not interrupt a blocked Read or Write;
// the revoke ends both, also while a process outside the session still
// holds the slave. The caller must own the slave or be root.
func RevokeTTY(path string) error { return unix.Revoke(path) }

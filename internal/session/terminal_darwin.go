//go:build darwin

package session

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

// waitExited blocks until the child pid exited and leaves it unreaped, so
// its pid and process group number stay reserved. x/sys has no waitid on
// macOS; a kqueue EVFILT_PROC NOTE_EXIT filter observes the exit without
// reaping. ESRCH at registration means the unreaped child already exited.
func waitExited(pid int) error {
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

// holdLeader holds the session leader by pid: macOS has no pidfd, so the pid
// may be reused between the end decision and the SIGKILL, at most
// terminalKillDelay later.
func holdLeader(pid int) (*sessionLeader, error) {
	return &sessionLeader{pid: pid, pidfd: -1}, nil
}

func (l *sessionLeader) signal(sig unix.Signal) error { return unix.Kill(l.pid, sig) }

func (l *sessionLeader) release() {}

// revokeSlave revokes every open of the slave. The master is a blocking
// file whose Close does not interrupt a blocked Read or Write; the revoke
// ends both, also while a process outside the session still holds the
// slave.
func revokeSlave(path string) error { return unix.Revoke(path) }

// hangupSession sends the SIGHUP of a terminal hangup to the foreground group
// and the session leader. The revoke runs before the master's real close
// (deferred while the reader blocks on the master) and detaches the slave
// from its session, so the kernel's hangup reaches nobody.
func hangupSession(foreground int, leader *sessionLeader) {
	if foreground > 0 {
		_ = unix.Kill(-foreground, unix.SIGHUP)
	}
	if leader != nil {
		_ = leader.signal(unix.SIGHUP)
	}
}

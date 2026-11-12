//go:build cgo && linux

package sessionhelper

import (
	"errors"

	"golang.org/x/sys/unix"
)

// holdLeader holds the session leader pid as a pidfd, so a reused pid is
// never signalled. A kernel without pidfd_open (before 5.3) gives ENOSYS:
// the leader is then held by its bare pid. ESRCH means it is gone.
func holdLeader(pid int) (*sessionLeader, error) {
	fd, err := unix.PidfdOpen(pid, 0)
	switch {
	case err == nil:
		return &sessionLeader{pid: pid, pidfd: fd}, nil
	case errors.Is(err, unix.ENOSYS):
		return &sessionLeader{pid: pid, pidfd: -1}, nil
	}
	return nil, err
}

func (l *sessionLeader) signal(sig unix.Signal) error {
	if l.pidfd >= 0 {
		return unix.PidfdSendSignal(l.pidfd, sig, nil, 0)
	}
	return unix.Kill(l.pid, sig)
}

func (l *sessionLeader) release() {
	if l.pidfd >= 0 {
		_ = unix.Close(l.pidfd)
	}
}

// hangupSession does nothing on Linux: the master's Close hangs up the
// slave, and the kernel sends SIGHUP to the session leader and the
// foreground group.
func hangupSession(int, *sessionLeader) {}

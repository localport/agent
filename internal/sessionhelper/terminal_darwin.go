//go:build cgo && darwin

package sessionhelper

import "golang.org/x/sys/unix"

// holdLeader holds the session leader by pid: macOS has no pidfd, so the pid
// may be reused between the end decision and the SIGKILL, at most
// terminalKillDelay later.
func holdLeader(pid int) (*sessionLeader, error) {
	return &sessionLeader{pid: pid, pidfd: -1}, nil
}

func (l *sessionLeader) signal(sig unix.Signal) error { return unix.Kill(l.pid, sig) }

func (l *sessionLeader) release() {}

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

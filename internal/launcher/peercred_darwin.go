package launcher

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerCred returns the peer's uid as of connect(2) (LOCAL_PEERCRED) and its
// pid (LOCAL_PEERPID). The pid is for logs only: it may be reused.
func peerCred(conn *net.UnixConn) (uid uint32, pid int, err error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *unix.Xucred
	var opErr error
	if err := rc.Control(func(fd uintptr) {
		cred, opErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if opErr == nil {
			pid, _ = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		}
	}); err != nil {
		return 0, 0, err
	}
	if opErr != nil {
		return 0, 0, opErr
	}
	return cred.Uid, pid, nil
}

// peerCredGroups returns the peer's uid and groups as of connect(2): the
// xucred's cr_groups, the effective gid first, at most 16 (NGROUPS).
func peerCredGroups(conn *net.UnixConn) (uint32, []uint32, error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return 0, nil, err
	}
	var cred *unix.Xucred
	var opErr error
	if err := rc.Control(func(fd uintptr) {
		cred, opErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, nil, err
	}
	if opErr != nil {
		return 0, nil, opErr
	}
	n := min(max(int(cred.Ngroups), 0), len(cred.Groups))
	return cred.Uid, append([]uint32(nil), cred.Groups[:n]...), nil
}

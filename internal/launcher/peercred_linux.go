package launcher

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerCred returns the peer's uid and pid as the kernel recorded them at
// connect(2) (SO_PEERCRED). The pid is for logs only: it may be reused.
func peerCred(conn *net.UnixConn) (uid uint32, pid int, err error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *unix.Ucred
	var opErr error
	if err := rc.Control(func(fd uintptr) {
		cred, opErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if opErr != nil {
		return 0, 0, opErr
	}
	return cred.Uid, int(cred.Pid), nil
}

package launcher

import (
	"errors"
	"net"
	"unsafe"

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

// maxPeerGroups bounds the supplementary groups read (NGROUPS_MAX is 65536).
const maxPeerGroups = 65536

// peerCredGroups returns the peer's uid and its groups as the kernel
// recorded them at connect(2): the primary gid (SO_PEERCRED) and the
// supplementary groups (SO_PEERGROUPS, Linux 4.13 and later; an older kernel
// yields the primary gid only).
func peerCredGroups(conn *net.UnixConn) (uint32, []uint32, error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return 0, nil, err
	}
	var (
		cred  *unix.Ucred
		gids  []uint32
		opErr error
	)
	if err := rc.Control(func(fd uintptr) {
		cred, opErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if opErr == nil {
			gids, opErr = peerGroups(int(fd))
		}
	}); err != nil {
		return 0, nil, err
	}
	if opErr != nil {
		return 0, nil, opErr
	}
	return cred.Uid, append(gids, cred.Gid), nil
}

// peerGroups reads SO_PEERGROUPS, growing the buffer on ERANGE, which
// reports the size needed.
func peerGroups(fd int) ([]uint32, error) {
	buf := make([]uint32, 64)
	for {
		size := uint32(len(buf) * 4)
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, unix.SO_PEERGROUPS,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
		switch {
		case errno == 0:
			return buf[:size/4], nil
		case errors.Is(errno, unix.ENOPROTOOPT):
			return nil, nil
		case errors.Is(errno, unix.ERANGE) && int(size/4) > len(buf) && size/4 <= maxPeerGroups:
			buf = make([]uint32, size/4)
		default:
			return nil, errno
		}
	}
}

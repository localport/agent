//go:build linux || darwin

package launcher

import (
	"errors"
	"io"
	"net"

	"golang.org/x/sys/unix"
)

// errControlTruncated refuses a message whose descriptors did not fit.
var errControlTruncated = errors.New("launcher: control message truncated")

// recvmsg runs one non-blocking recvmsg on conn when it is readable. wrap,
// when not nil, runs around each attempt; receive returns the control bytes
// of that attempt so wrap can act on its descriptors before releasing.
func recvmsg(conn *net.UnixConn, buf, oob []byte, flags int, wrap func(receive func() []byte)) (n, oobn int, err error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var recvFlags int
	var opErr error
	readErr := rc.Read(func(fd uintptr) bool {
		receive := func() []byte {
			n, oobn, recvFlags, _, opErr = unix.Recvmsg(int(fd), buf, oob, flags)
			if opErr != nil {
				return nil
			}
			return oob[:oobn]
		}
		if wrap != nil {
			wrap(receive)
		} else {
			receive()
		}
		return !errors.Is(opErr, unix.EAGAIN)
	})
	if readErr != nil {
		return 0, 0, readErr
	}
	if opErr != nil {
		return 0, 0, opErr
	}
	if recvFlags&unix.MSG_CTRUNC != 0 {
		if fds, err := parseRights(oob[:oobn]); err == nil {
			for _, fd := range fds {
				_ = unix.Close(fd)
			}
		}
		return 0, 0, errControlTruncated
	}
	if n == 0 && oobn == 0 {
		return 0, 0, io.EOF
	}
	return n, oobn, nil
}

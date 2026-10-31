package launcher

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// recvmsgCloexec is one recvmsg whose received descriptors are made
// close-on-exec before any fork can copy them: macOS has no
// MSG_CMSG_CLOEXEC, so each non-blocking receive and the fcntl after it run
// under the write side of syscall.ForkLock, which os/exec takes for reading
// around every fork. The wait for readability holds no lock.
func recvmsgCloexec(conn *net.UnixConn, buf, oob []byte) (n, oobn int, err error) {
	return recvmsg(conn, buf, oob, 0, func(receive func() []byte) {
		syscall.ForkLock.Lock()
		defer syscall.ForkLock.Unlock()
		got := receive()
		if fds, err := parseRights(got); err == nil {
			for _, fd := range fds {
				unix.CloseOnExec(fd)
			}
		}
	})
}

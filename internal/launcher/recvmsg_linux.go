package launcher

import (
	"net"

	"golang.org/x/sys/unix"
)

// recvmsgCloexec is one recvmsg whose received descriptors are close-on-exec
// atomically (MSG_CMSG_CLOEXEC). A truncated control message is refused.
func recvmsgCloexec(conn *net.UnixConn, buf, oob []byte) (n, oobn int, err error) {
	return recvmsg(conn, buf, oob, unix.MSG_CMSG_CLOEXEC, nil)
}

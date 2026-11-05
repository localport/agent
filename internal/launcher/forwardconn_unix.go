//go:build linux || darwin

package launcher

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// maxQueuedFDs bounds the received descriptors waiting for their message.
// Each fd-bearing message carries one and is decoded as soon as it is whole,
// so more than a handful queued means the helper is sending stray ones.
const maxQueuedFDs = 8

// unixForwardTransport is the agent's end of a forward helper's session
// socket: messages arrive with the descriptors of dialed and accepted
// sockets attached (SCM_RIGHTS), queued in arrival order. The stream and
// the descriptors keep the sender's order, so the next fd-bearing message
// takes the oldest queued descriptor.
type unixForwardTransport struct {
	conn *net.UnixConn
	oob  []byte

	mu  sync.Mutex
	fds []*os.File
}

// newForwardTransport is the agent's end of a forward helper's session
// socket; it owns channel.
func newForwardTransport(channel *os.File, _ func(string, ...any)) (forwardTransport, error) {
	nc, err := net.FileConn(channel)
	_ = channel.Close()
	if err != nil {
		return nil, err
	}
	uc, ok := nc.(*net.UnixConn)
	if !ok {
		_ = nc.Close()
		return nil, errors.New("launcher: the forward channel is not a unix socket")
	}
	return &unixForwardTransport{conn: uc, oob: make([]byte, unix.CmsgSpace(4*maxQueuedFDs))}, nil
}

func (t *unixForwardTransport) Read(p []byte) (int, error) {
	n, oobn, err := recvmsgCloexec(t.conn, p, t.oob)
	if err != nil {
		return 0, err
	}
	fds, err := parseRights(t.oob[:oobn])
	if err != nil {
		return 0, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, fd := range fds {
		t.fds = append(t.fds, os.NewFile(uintptr(fd), "forward-socket"))
	}
	if len(t.fds) > maxQueuedFDs {
		return 0, fmt.Errorf("%w: descriptors without their messages", errBadForward)
	}
	return n, nil
}

func (t *unixForwardTransport) writeMsg(b []byte) error {
	_, err := t.conn.Write(b)
	return err
}

func (t *unixForwardTransport) takeFD() *os.File {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.fds) == 0 {
		return nil
	}
	f := t.fds[0]
	t.fds = t.fds[1:]
	return f
}

func (t *unixForwardTransport) passesFDs() bool { return true }
func (t *unixForwardTransport) Close() error    { return t.conn.Close() }

// WriteForwardMsg writes m on the helper's end of a forward channel, with
// sock's descriptor attached when sock is not nil (an ok for a dial, an
// accepted). The caller serializes writers and closes sock afterwards.
func WriteForwardMsg(conn *net.UnixConn, m FwdMsg, sock *os.File) error {
	b, err := AppendForwardMsg(nil, m)
	if err != nil {
		return err
	}
	var oob []byte
	if sock != nil {
		oob = unix.UnixRights(int(sock.Fd()))
	}
	n, oobn, err := conn.WriteMsgUnix(b, oob, nil)
	if err != nil {
		return err
	}
	if oobn != len(oob) {
		return errors.New("launcher: descriptor not sent")
	}
	if n < len(b) {
		_, err = conn.Write(b[n:])
	}
	return err
}

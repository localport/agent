//go:build linux || darwin

package launcher

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// sendMessage writes v as one message on conn, with fd attached to its
// first byte when fd is not nil.
func sendMessage(conn *net.UnixConn, v any, fd *os.File) error {
	b, err := encode(v)
	if err != nil {
		return err
	}
	var oob []byte
	if fd != nil {
		oob = unix.UnixRights(int(fd.Fd()))
	}
	n, oobn, err := conn.WriteMsgUnix(b, oob, nil)
	if err != nil {
		return err
	}
	if oobn != len(oob) {
		return fmt.Errorf("launcher: descriptor not sent")
	}
	if n < len(b) {
		_, err = conn.Write(b[n:])
	}
	return err
}

// recvRequest reads one request and the descriptor attached to it, if any.
// Every received descriptor is close-on-exec before anything can fork; more
// than one descriptor is a bad request and all are closed.
func recvRequest(conn *net.UnixConn) (Request, *os.File, error) {
	buf := make([]byte, 4+MaxMessage)
	oob := make([]byte, unix.CmsgSpace(4*4))
	n, oobn, err := recvmsgCloexec(conn, buf, oob)
	if err != nil {
		return Request{}, nil, err
	}
	fds, err := parseRights(oob[:oobn])
	if err != nil {
		return Request{}, nil, err
	}
	var fd *os.File
	if len(fds) > 1 {
		for _, f := range fds {
			_ = unix.Close(f)
		}
		return Request{}, nil, Refusal(CodeBadRequest)
	}
	if len(fds) == 1 {
		fd = os.NewFile(uintptr(fds[0]), "session-channel")
	}
	fail := func(err error) (Request, *os.File, error) {
		if fd != nil {
			_ = fd.Close()
		}
		return Request{}, nil, err
	}
	for n < 4 {
		m, err := conn.Read(buf[n:])
		if err != nil {
			return fail(err)
		}
		n += m
	}
	size := int(binary.BigEndian.Uint32(buf))
	if size == 0 || size > MaxMessage {
		return fail(Refusal(CodeBadRequest))
	}
	for n < 4+size {
		m, err := conn.Read(buf[n : 4+size])
		if err != nil {
			return fail(err)
		}
		n += m
	}
	if n != 4+size {
		// Bytes past the one request: a client of this protocol sends none.
		return fail(Refusal(CodeBadRequest))
	}
	req, err := decodeRequest(buf[4:n])
	if err != nil {
		return fail(err)
	}
	return req, fd, nil
}

func parseRights(oob []byte) ([]int, error) {
	if len(oob) == 0 {
		return nil, nil
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("launcher: control message: %w", err)
	}
	var fds []int
	for _, m := range msgs {
		if m.Header.Level != syscall.SOL_SOCKET || m.Header.Type != syscall.SCM_RIGHTS {
			continue
		}
		got, err := unix.ParseUnixRights(&m)
		if err != nil {
			return nil, fmt.Errorf("launcher: rights: %w", err)
		}
		fds = append(fds, got...)
	}
	return fds, nil
}

//go:build unix

package sessionhelper

import (
	"errors"
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/localport/agent/internal/launcher"
)

// unixForwardSupported: unix socket forwards are served on Linux and macOS.
const unixForwardSupported = true

// forwardSocketMask is the forward server's umask: a remote unix socket
// forward's socket is 0600, as OpenSSH's StreamLocalBindMask 0177.
const forwardSocketMask = 0o177

// RunForwardServer is `localport-session forward-server`: it serves the
// forward channel on descriptor 3 until the agent closes it.
func RunForwardServer(log func(string, ...any)) error {
	syscall.Umask(forwardSocketMask)
	f := os.NewFile(3, "forward-channel")
	if f == nil {
		return errors.New("started without the forward channel")
	}
	nc, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		return err
	}
	uc, ok := nc.(*net.UnixConn)
	if !ok {
		_ = nc.Close()
		return errors.New("the forward channel is not a unix socket")
	}
	defer uc.Close()
	return ServeForwardSocket(uc, log)
}

// ServeForwardSocket serves a forward channel socket as the current user;
// the agent's end is a launcher.ForwardClient.
func ServeForwardSocket(uc *net.UnixConn, log func(string, ...any)) error {
	return ServeForwards(&unixForwardPeer{conn: uc}, log)
}

// unixForwardPeer passes each connected socket to the agent as a descriptor;
// the agent then relays it with no copy through this process.
type unixForwardPeer struct {
	conn *net.UnixConn
	wmu  sync.Mutex
}

func (p *unixForwardPeer) Read(b []byte) (int, error) { return p.conn.Read(b) }

func (p *unixForwardPeer) send(m launcher.FwdMsg, conn net.Conn) error {
	var sock *os.File
	if conn != nil {
		fc, ok := conn.(interface{ File() (*os.File, error) })
		if !ok {
			_ = conn.Close()
			return errors.New("forward: the connection has no descriptor")
		}
		var err error
		sock, err = fc.File()
		_ = conn.Close()
		if err != nil {
			return err
		}
		defer sock.Close()
	}
	p.wmu.Lock()
	defer p.wmu.Unlock()
	return launcher.WriteForwardMsg(p.conn, m, sock)
}

// deliver accepts only a close: the agent owns every passed socket, so a
// close names one this process no longer holds.
func (p *unixForwardPeer) deliver(m launcher.FwdMsg) error {
	if m.Type == launcher.FwdClose {
		return nil
	}
	return errors.New("forward: stream data where sockets pass")
}

func (p *unixForwardPeer) conns() int { return 0 }
func (p *unixForwardPeer) closeAll()  {}

func errConnRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }
func errAddrInUse(err error) bool   { return errors.Is(err, syscall.EADDRINUSE) }
func errPermission(err error) bool {
	return errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
}

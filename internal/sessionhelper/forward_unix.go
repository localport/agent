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
// the agent then relays it with no copy through this process. It keeps its
// copy of each passed socket (held, by message id) until the agent's ack: on
// macOS a socket whose only reference is an in-flight SCM_RIGHTS message can
// be torn down before the agent receives it. Held sockets count as carried
// forwards (conns), so the server's dial and accept limits bound them.
type unixForwardPeer struct {
	conn *net.UnixConn
	wmu  sync.Mutex

	hmu  sync.Mutex
	held map[uint32]*os.File
	// closed is set by closeAll; a later send closes its socket at once.
	closed bool
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
		// Held before the write: the agent's ack may arrive before the write
		// returns.
		p.hmu.Lock()
		closed := p.closed
		if !closed {
			if p.held == nil {
				p.held = map[uint32]*os.File{}
			}
			p.held[m.ID] = sock
		}
		p.hmu.Unlock()
		if closed {
			_ = sock.Close()
			return net.ErrClosed
		}
	}
	p.wmu.Lock()
	err := launcher.WriteForwardMsg(p.conn, m, sock)
	p.wmu.Unlock()
	if err != nil && sock != nil {
		p.hmu.Lock()
		if p.held[m.ID] == sock {
			delete(p.held, m.ID)
			_ = sock.Close()
		}
		p.hmu.Unlock()
	}
	return err
}

// deliver accepts a close and an ack. The agent owns every passed socket,
// so a close names one this process holds at most until its ack; the ack
// releases that copy, and an ack of no held socket ends the server.
func (p *unixForwardPeer) deliver(m launcher.FwdMsg) error {
	switch m.Type {
	case launcher.FwdClose:
		return nil
	case launcher.FwdAck:
		p.hmu.Lock()
		sock := p.held[m.ID]
		delete(p.held, m.ID)
		p.hmu.Unlock()
		if sock == nil {
			return errors.New("forward: an ack of no passed socket")
		}
		return sock.Close()
	}
	return errors.New("forward: stream data where sockets pass")
}

func (p *unixForwardPeer) conns() int {
	p.hmu.Lock()
	defer p.hmu.Unlock()
	return len(p.held)
}

// closeAll releases every passed socket not yet acked, and makes every later
// send close its socket instead of holding it.
func (p *unixForwardPeer) closeAll() {
	p.hmu.Lock()
	held := p.held
	p.held, p.closed = nil, true
	p.hmu.Unlock()
	for _, sock := range held {
		_ = sock.Close()
	}
}

func errConnRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }
func errAddrInUse(err error) bool   { return errors.Is(err, syscall.EADDRINUSE) }
func errPermission(err error) bool {
	return errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
}

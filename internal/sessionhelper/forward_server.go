package sessionhelper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/localport/agent/internal/launcher"
)

// ForwardServerMode is the argument that runs the forward server: one SSH
// connection's networking helper, started by the helper as the login.
const ForwardServerMode = "forward-server"

const (
	// maxForwardListeners bounds the remote listeners of one connection.
	maxForwardListeners = 8
	// maxForwardConns bounds the dials in progress, and on Windows the
	// streams, of one connection.
	maxForwardConns = 32
	// forwardDialTimeout bounds one dial.
	forwardDialTimeout = 30 * time.Second
)

// forwardPeer is the forward server's end of its channel to the agent.
type forwardPeer interface {
	io.Reader
	// send writes m. With conn (an ok for a dial, an accepted) the
	// connection goes with it: as a descriptor that send closes here (Linux
	// and macOS), or as a new stream of m.ID that send pumps (Windows).
	send(m launcher.FwdMsg, conn net.Conn) error
	// deliver applies a stream message (data, eof, window, or a close of no
	// listener); an error ends the server.
	deliver(m launcher.FwdMsg) error
	// conns is the number of forwards the peer carries (Windows streams).
	conns() int
	// closeAll ends every carried forward.
	closeAll()
}

// forwardServer is the state of ServeForwards.
type forwardServer struct {
	peer forwardPeer
	log  func(string, ...any)
	ctx  context.Context

	mu          sync.Mutex
	lastAgentID uint32
	dialing     int
	listeners   map[uint32]net.Listener

	// amu serializes allocating an accepted id with sending it, so ids reach
	// the agent in increasing order, which it requires.
	amu          sync.Mutex
	nextAccepted uint32
}

// ServeForwards serves the agent's dial, listen and close requests on peer
// until the channel ends or a message fails decoding. Every listener closes
// (removing its socket file) and every dial in progress is cancelled before
// it returns.
func ServeForwards(peer forwardPeer, log func(string, ...any)) error {
	ctx, cancel := context.WithCancel(context.Background())
	s := &forwardServer{peer: peer, log: log, ctx: ctx, nextAccepted: 1, listeners: map[uint32]net.Listener{}}
	var wg sync.WaitGroup
	defer func() {
		cancel()
		s.mu.Lock()
		listeners := s.listeners
		s.listeners = nil
		s.mu.Unlock()
		for _, ln := range listeners {
			_ = ln.Close()
		}
		peer.closeAll()
		wg.Wait()
	}()
	fr := launcher.NewForwardReader(peer)
	for {
		m, err := fr.Read()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := s.handle(m, &wg); err != nil {
			return err
		}
	}
}

func (s *forwardServer) handle(m launcher.FwdMsg, wg *sync.WaitGroup) error {
	switch m.Type {
	case launcher.FwdDial, launcher.FwdListen:
		s.mu.Lock()
		if m.ID <= s.lastAgentID {
			s.mu.Unlock()
			return fmt.Errorf("forward: a reused request id %d", m.ID)
		}
		s.lastAgentID = m.ID
		if m.Type == launcher.FwdListen {
			n := len(s.listeners)
			s.mu.Unlock()
			if n >= maxForwardListeners {
				return s.refuse(m.ID, launcher.FwdCodeLimit)
			}
			return s.listen(m, wg)
		}
		if s.dialing+s.peer.conns() >= maxForwardConns {
			s.mu.Unlock()
			return s.refuse(m.ID, launcher.FwdCodeLimit)
		}
		s.dialing++
		s.mu.Unlock()
		wg.Go(func() { s.dial(m) })
		return nil
	case launcher.FwdClose:
		s.mu.Lock()
		ln := s.listeners[m.ID]
		delete(s.listeners, m.ID)
		s.mu.Unlock()
		if ln != nil {
			return ln.Close()
		}
		return s.peer.deliver(m)
	case launcher.FwdData, launcher.FwdEOF, launcher.FwdWindow:
		return s.peer.deliver(m)
	}
	return fmt.Errorf("forward: message type %d from the agent", m.Type)
}

func (s *forwardServer) refuse(id uint32, code byte) error {
	return s.peer.send(launcher.FwdMsg{Type: launcher.FwdRefused, ID: id, Code: code}, nil)
}

// dial connects to the request's target as this process's user and answers.
// A failed answer means the channel ended; the read loop sees it too.
func (s *forwardServer) dial(m launcher.FwdMsg) {
	defer func() {
		s.mu.Lock()
		s.dialing--
		s.mu.Unlock()
	}()
	network, addr := "unix", m.Path
	if m.Network == launcher.FwdTCP {
		network, addr = "tcp", net.JoinHostPort(m.Host, strconv.Itoa(int(m.Port)))
	}
	if m.Network == launcher.FwdUnix && !unixForwardSupported {
		_ = s.refuse(m.ID, launcher.FwdCodeUnsupported)
		return
	}
	d := net.Dialer{Timeout: forwardDialTimeout}
	conn, err := d.DialContext(s.ctx, network, addr)
	if err != nil {
		s.log("forward: dial %s %q: %v", network, addr, err)
		_ = s.refuse(m.ID, dialErrorCode(err))
		return
	}
	if err := s.peer.send(launcher.FwdMsg{Type: launcher.FwdOK, ID: m.ID}, conn); err != nil {
		_ = conn.Close()
	}
}

// listen opens a loopback or unix socket listener and serves its accepts.
func (s *forwardServer) listen(m launcher.FwdMsg, wg *sync.WaitGroup) error {
	var ln net.Listener
	var err error
	switch {
	case m.Network == launcher.FwdUnix && !unixForwardSupported:
		return s.refuse(m.ID, launcher.FwdCodeUnsupported)
	case m.Network == launcher.FwdUnix:
		// The process umask (0177, set at start) makes the socket 0600.
		ln, err = net.Listen("unix", m.Path)
	default:
		host := "127.0.0.1"
		if m.IPv6 {
			host = "::1"
		}
		ln, err = net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(int(m.Port))))
	}
	if err != nil {
		return s.refuse(m.ID, listenErrorCode(err, m.Network == launcher.FwdUnix))
	}
	var port uint16
	if a, ok := ln.Addr().(*net.TCPAddr); ok {
		port = uint16(a.Port)
	}
	s.mu.Lock()
	if s.listeners == nil {
		s.mu.Unlock()
		_ = ln.Close()
		return nil
	}
	s.listeners[m.ID] = ln
	s.mu.Unlock()
	if err := s.peer.send(launcher.FwdMsg{Type: launcher.FwdOK, ID: m.ID, Port: port}, nil); err != nil {
		return err
	}
	wg.Go(func() { s.accept(m.ID, ln) })
	return nil
}

// accept reports each connection ln accepts until ln closes. A listener
// that fails on its own is reported closed; one the agent closed is not.
func (s *forwardServer) accept(id uint32, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			own := s.listeners != nil && s.listeners[id] == ln
			if own {
				delete(s.listeners, id)
			}
			s.mu.Unlock()
			if own {
				_ = ln.Close()
				_ = s.peer.send(launcher.FwdMsg{Type: launcher.FwdClose, ID: id}, nil)
			}
			return
		}
		if s.peer.conns() >= maxForwardConns {
			_ = conn.Close()
			continue
		}
		m := launcher.FwdMsg{Type: launcher.FwdAccepted, ListenerID: id}
		if a, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			m.Host, m.Port = a.IP.String(), uint16(a.Port)
		}
		s.amu.Lock()
		m.ID = s.nextAccepted
		s.nextAccepted += 2
		err = s.peer.send(m, conn)
		s.amu.Unlock()
		if err != nil {
			_ = conn.Close()
			return
		}
	}
}

// dialErrorCode maps a dial failure to its refusal code.
func dialErrorCode(err error) byte {
	switch {
	case errConnRefused(err):
		return launcher.FwdCodeConnectionRefused
	case errPermission(err):
		return launcher.FwdCodePermissionDenied
	}
	return launcher.FwdCodeUnreachable
}

// listenErrorCode maps a listen failure to its refusal code; an address in
// use on a unix socket is its path existing.
func listenErrorCode(err error, unixSocket bool) byte {
	switch {
	case errAddrInUse(err) && unixSocket:
		return launcher.FwdCodePathExists
	case errAddrInUse(err):
		return launcher.FwdCodeAddressInUse
	case errPermission(err):
		return launcher.FwdCodePermissionDenied
	}
	return launcher.FwdCodeInvalid
}

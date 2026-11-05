package launcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
)

// ForwardConn is one forwarded connection: a socket the helper passed (Linux
// and macOS) or a ForwardStream (Windows).
type ForwardConn interface {
	io.ReadWriteCloser
	CloseWrite() error
}

// Accepted is one connection a remote listener accepted.
type Accepted struct {
	Conn ForwardConn
	// Host and Port are the connection's origin; empty and 0 for a unix
	// socket.
	Host string
	Port uint16
}

// ForwardRefusal is a dial or listen the helper refused, with its code.
type ForwardRefusal struct{ Code byte }

func (e *ForwardRefusal) Error() string { return "forward refused: " + FwdCodeName(e.Code) }

// ErrForwardHelperFailed is every forward request after the helper's channel
// ended or broke the protocol.
var ErrForwardHelperFailed = errors.New("launcher: the forward helper ended")

// forwardTransport is the agent's side of a forward helper's channel: the
// message byte stream, whole-message writes, and on Linux and macOS the
// descriptors received with it, in order.
type forwardTransport interface {
	io.Reader
	writeMsg(b []byte) error
	// takeFD returns the next received descriptor; nil when none is queued.
	takeFD() *os.File
	// passesFDs reports whether sockets cross as descriptors; false carries
	// them as ForwardMux streams.
	passesFDs() bool
	Close() error
}

type pendingForward struct {
	listen    bool
	abandoned bool
	reply     chan forwardReply
	listener  *forwardListener
}

type forwardReply struct {
	id   uint32
	conn ForwardConn
	port uint16
	err  error
}

type forwardListener struct {
	accept func(Accepted)
	closed func()
}

// ForwardClient is the agent's end of one forward helper: it allocates the
// even ids, matches each answer to its request, hands accepted connections
// to their listener's callback and, on Windows, carries the streams. It is
// safe for concurrent use. When the channel ends or the helper breaks the
// protocol, every pending request fails with ErrForwardHelperFailed, every
// listener's closed callback runs, and Done closes.
type ForwardClient struct {
	t   forwardTransport
	mux *ForwardMux
	log func(format string, args ...any)

	wmu sync.Mutex
	buf []byte

	mu           sync.Mutex
	nextID       uint32
	lastAccepted uint32
	pending      map[uint32]*pendingForward
	listeners    map[uint32]*forwardListener
	failed       bool

	done chan struct{}
}

// NewForwardClient serves the agent's end of a started forward helper's
// session channel. The client owns channel and closes it on Close or when
// the helper ends.
func NewForwardClient(channel *os.File, log func(string, ...any)) (*ForwardClient, error) {
	t, err := newForwardTransport(channel, log)
	if err != nil {
		return nil, err
	}
	return newForwardClient(t, log), nil
}

func newForwardClient(t forwardTransport, log func(string, ...any)) *ForwardClient {
	c := &ForwardClient{t: t, log: log, pending: map[uint32]*pendingForward{},
		listeners: map[uint32]*forwardListener{}, done: make(chan struct{})}
	if !t.passesFDs() {
		c.mux = NewForwardMux(c.send)
	}
	go c.read()
	return c
}

// Done is closed once the helper's channel ended.
func (c *ForwardClient) Done() <-chan struct{} { return c.done }

// Close ends the helper's channel; the helper ends every forward and exits.
func (c *ForwardClient) Close() error { return c.t.Close() }

func (c *ForwardClient) send(m FwdMsg) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	b, err := AppendForwardMsg(c.buf[:0], m)
	if err != nil {
		return err
	}
	c.buf = b
	return c.t.writeMsg(b)
}

// Dial asks the helper to connect to host:port (FwdTCP) or path (FwdUnix)
// as the login. A refusal is a *ForwardRefusal.
func (c *ForwardClient) Dial(ctx context.Context, network byte, host string, port uint16, path string) (ForwardConn, error) {
	r, err := c.request(ctx, FwdMsg{Type: FwdDial, Network: network, Host: host, Port: port, Path: path}, nil)
	return r.conn, err
}

// Listen asks the helper to listen on loopback port (FwdTCP; 0 picks one,
// ipv6 binds ::1, else 127.0.0.1) or on path (FwdUnix) as the login. accept
// runs on the client's reader for each accepted connection and must not
// block; closed runs once when the listener ends without CloseListener (the
// helper ended). It returns the listener's id and its bound port.
func (c *ForwardClient) Listen(ctx context.Context, network byte, port uint16, ipv6 bool, path string, accept func(Accepted), closed func()) (uint32, uint16, error) {
	l := &forwardListener{accept: accept, closed: closed}
	m := FwdMsg{Type: FwdListen, Network: network, Port: port, IPv6: ipv6, Path: path}
	r, err := c.request(ctx, m, l)
	if err != nil {
		return 0, 0, err
	}
	return r.id, r.port, nil
}

// CloseListener closes listener id: the helper closes it and removes its
// socket file. Connections it accepted stay open.
func (c *ForwardClient) CloseListener(id uint32) {
	c.mu.Lock()
	_, ok := c.listeners[id]
	delete(c.listeners, id)
	c.mu.Unlock()
	if ok {
		_ = c.send(FwdMsg{Type: FwdClose, ID: id})
	}
}

// request sends m with a fresh even id and waits for its answer, ctx or the
// helper's end. An answer arriving after ctx ended is closed by the reader.
func (c *ForwardClient) request(ctx context.Context, m FwdMsg, l *forwardListener) (forwardReply, error) {
	c.mu.Lock()
	if c.failed {
		c.mu.Unlock()
		return forwardReply{}, ErrForwardHelperFailed
	}
	c.nextID += 2
	m.ID = c.nextID
	p := &pendingForward{listen: m.Type == FwdListen, reply: make(chan forwardReply, 1), listener: l}
	c.pending[m.ID] = p
	c.mu.Unlock()
	if err := c.send(m); err != nil {
		c.abandon(m.ID)
		if errors.Is(err, errBadForward) {
			return forwardReply{}, &ForwardRefusal{Code: FwdCodeInvalid}
		}
		return forwardReply{}, fmt.Errorf("%w: %w", ErrForwardHelperFailed, err)
	}
	select {
	case r := <-p.reply:
		r.id = m.ID
		return r, r.err
	case <-ctx.Done():
		c.abandon(m.ID)
		return forwardReply{}, ctx.Err()
	}
}

func (c *ForwardClient) abandon(id uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p := c.pending[id]; p != nil {
		p.abandoned = true
	}
}

// read serves the helper's messages until the channel ends or breaks the
// protocol, then fails everything still waiting.
func (c *ForwardClient) read() {
	fr := NewForwardReader(c.t)
	var err error
	for err == nil {
		var m FwdMsg
		if m, err = fr.Read(); err == nil {
			err = c.handle(m)
		}
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrClosed) && !errors.Is(err, net.ErrClosed) {
		c.log("launcher: forward helper channel: %v", err)
	}
	_ = c.t.Close()
	c.mu.Lock()
	c.failed = true
	pending, listeners := c.pending, c.listeners
	c.pending, c.listeners = map[uint32]*pendingForward{}, map[uint32]*forwardListener{}
	c.mu.Unlock()
	if c.mux != nil {
		c.mux.CloseAll()
	}
	for _, p := range pending {
		p.reply <- forwardReply{err: ErrForwardHelperFailed}
	}
	for _, l := range listeners {
		if l.closed != nil {
			l.closed()
		}
	}
	for f := c.t.takeFD(); f != nil; f = c.t.takeFD() {
		_ = f.Close()
	}
	close(c.done)
}

// handle applies one helper message; an error ends the client.
func (c *ForwardClient) handle(m FwdMsg) error {
	switch m.Type {
	case FwdOK, FwdRefused:
		c.mu.Lock()
		p := c.pending[m.ID]
		delete(c.pending, m.ID)
		if p != nil && m.Type == FwdOK && p.listen && !p.abandoned {
			c.listeners[m.ID] = p.listener
		}
		c.mu.Unlock()
		if p == nil {
			return fmt.Errorf("%w: an answer to no request", errBadForward)
		}
		if m.Type == FwdRefused {
			if !p.abandoned {
				p.reply <- forwardReply{err: &ForwardRefusal{Code: m.Code}}
			}
			return nil
		}
		if p.listen {
			if p.abandoned {
				_ = c.send(FwdMsg{Type: FwdClose, ID: m.ID})
				return nil
			}
			p.reply <- forwardReply{port: m.Port}
			return nil
		}
		if m.Port != 0 {
			return fmt.Errorf("%w: a dial answer with a port", errBadForward)
		}
		conn, err := c.conn(m.ID)
		if err != nil {
			return err
		}
		if p.abandoned {
			_ = conn.Close()
			return nil
		}
		p.reply <- forwardReply{conn: conn}
		return nil
	case FwdAccepted:
		c.mu.Lock()
		if m.ID <= c.lastAccepted {
			c.mu.Unlock()
			return fmt.Errorf("%w: a reused accepted id", errBadForward)
		}
		c.lastAccepted = m.ID
		l := c.listeners[m.ListenerID]
		c.mu.Unlock()
		conn, err := c.conn(m.ID)
		if err != nil {
			return err
		}
		if l == nil {
			// The listener closed while the connection was in flight.
			_ = conn.Close()
			return nil
		}
		l.accept(Accepted{Conn: conn, Host: m.Host, Port: m.Port})
		return nil
	case FwdClose:
		c.mu.Lock()
		l := c.listeners[m.ID]
		delete(c.listeners, m.ID)
		c.mu.Unlock()
		if l != nil {
			if l.closed != nil {
				l.closed()
			}
			return nil
		}
		if c.mux != nil {
			return c.mux.Deliver(m)
		}
		return nil
	case FwdData, FwdEOF, FwdWindow:
		if c.mux == nil {
			return fmt.Errorf("%w: stream data where sockets pass", errBadForward)
		}
		return c.mux.Deliver(m)
	}
	return fmt.Errorf("%w: type %d from the helper", errBadForward, m.Type)
}

// conn is the connection of an ok dial or an accepted: the next received
// descriptor, or a new stream.
func (c *ForwardClient) conn(id uint32) (ForwardConn, error) {
	if c.mux != nil {
		return c.mux.Open(id)
	}
	f := c.t.takeFD()
	if f == nil {
		return nil, fmt.Errorf("%w: no socket with the message", errBadForward)
	}
	defer f.Close()
	nc, err := net.FileConn(f)
	if err != nil {
		return nil, err
	}
	fc, ok := nc.(ForwardConn)
	if !ok {
		_ = nc.Close()
		return nil, fmt.Errorf("%w: the passed socket is not a stream", errBadForward)
	}
	return fc, nil
}

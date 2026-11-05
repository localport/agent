package launcher

import (
	"errors"
	"io"
	"sync"
)

// ForwardMux carries forward streams as data, eof, window and close messages
// on one message channel (Windows, where no socket crosses the process
// boundary). Each stream grants its peer ForwardWindow bytes of credit per
// direction: a sender never has more unacknowledged bytes in flight, and a
// receiver acknowledges with window as its reader consumes them. A peer that
// sends past its credit breaks the protocol (Deliver fails), so one stream's
// receive buffer never exceeds ForwardWindow and delivery never blocks.
type ForwardMux struct {
	send func(FwdMsg) error

	mu      sync.Mutex
	streams map[uint32]*ForwardStream
	closed  bool
}

// NewForwardMux returns a mux whose messages go out through send, which
// serializes its callers.
func NewForwardMux(send func(FwdMsg) error) *ForwardMux {
	return &ForwardMux{send: send, streams: map[uint32]*ForwardStream{}}
}

// errStreamClosed is a read or write on a stream either side closed.
var errStreamClosed = errors.New("launcher: forward stream closed")

// Open registers stream id with a full window both ways. It fails for an id
// in use or after CloseAll.
func (m *ForwardMux) Open(id uint32) (*ForwardStream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.streams[id] != nil {
		return nil, errBadForward
	}
	s := &ForwardStream{m: m, id: id, credit: ForwardWindow}
	s.cond = sync.NewCond(&s.mu)
	m.streams[id] = s
	return s, nil
}

// Len is the number of open streams.
func (m *ForwardMux) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.streams)
}

// Deliver applies one data, eof, window or close message from the peer. A
// message for an unknown id is ignored (the stream closed here while it was
// in flight); a data message past the stream's window, or a window past the
// sender's grant, is a protocol error.
func (m *ForwardMux) Deliver(msg FwdMsg) error {
	m.mu.Lock()
	s := m.streams[msg.ID]
	if msg.Type == FwdClose && s != nil {
		delete(m.streams, msg.ID)
	}
	m.mu.Unlock()
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.cond.Broadcast()
	switch msg.Type {
	case FwdData:
		if s.eof || s.peerClosed || len(s.buf)+len(msg.Data) > ForwardWindow {
			return errBadForward
		}
		if !s.closed {
			s.buf = append(s.buf, msg.Data...)
		}
	case FwdEOF:
		s.eof = true
	case FwdWindow:
		if s.credit+int(msg.N) > ForwardWindow {
			return errBadForward
		}
		s.credit += int(msg.N)
	case FwdClose:
		// Bytes already received stay readable.
		s.peerClosed = true
	default:
		return errBadForward
	}
	return nil
}

// CloseAll closes every stream without telling the peer: the channel ended.
func (m *ForwardMux) CloseAll() {
	m.mu.Lock()
	streams := m.streams
	m.streams, m.closed = map[uint32]*ForwardStream{}, true
	m.mu.Unlock()
	for _, s := range streams {
		s.mu.Lock()
		s.closed, s.peerClosed, s.buf = true, true, nil
		s.cond.Broadcast()
		s.mu.Unlock()
	}
}

// ForwardStream is one forward carried by a ForwardMux. Read, Write,
// CloseWrite and Close are safe for concurrent use; Close wakes a blocked
// Read or Write.
type ForwardStream struct {
	m  *ForwardMux
	id uint32

	mu   sync.Mutex
	cond *sync.Cond
	// buf holds received bytes the reader has not taken; unacked counts the
	// bytes taken and not yet acknowledged with window.
	buf     []byte
	unacked int
	// credit is the bytes this side may still send.
	credit int
	eof    bool
	// wclosed is set once eof went out; closed once this side closed the
	// stream; peerClosed once the peer did (no close goes back, and received
	// bytes stay readable).
	wclosed    bool
	closed     bool
	peerClosed bool
}

// ID is the stream's forward id.
func (s *ForwardStream) ID() uint32 { return s.id }

// Read reads received bytes; io.EOF after the peer's eof once drained.
func (s *ForwardStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	for len(s.buf) == 0 && !s.eof && !s.closed && !s.peerClosed {
		s.cond.Wait()
	}
	if len(s.buf) == 0 {
		// After the peer's eof the stream reads EOF; after a close by either
		// side (bytes received before a peer close drained first) it fails,
		// so a relay tears the forward down rather than half-closing it.
		closed := s.closed || s.peerClosed
		s.mu.Unlock()
		if closed {
			return 0, errStreamClosed
		}
		return 0, io.EOF
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	if len(s.buf) == 0 {
		s.buf = nil
	}
	s.unacked += n
	var ack int
	// Acknowledge in halves of the window, so the sender is never starved
	// and window messages stay few.
	if s.unacked >= ForwardWindow/2 || (len(s.buf) == 0 && s.unacked > 0) {
		ack, s.unacked = s.unacked, 0
	}
	s.mu.Unlock()
	if ack > 0 {
		if err := s.m.send(FwdMsg{Type: FwdWindow, ID: s.id, N: uint32(ack)}); err != nil {
			return n, err
		}
	}
	return n, nil
}

// Write sends p as data messages within the peer's credit, blocking while
// the credit is spent.
func (s *ForwardStream) Write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		s.mu.Lock()
		for s.credit == 0 && !s.closed && !s.wclosed && !s.peerClosed {
			s.cond.Wait()
		}
		if s.closed || s.wclosed || s.peerClosed {
			s.mu.Unlock()
			return written, errStreamClosed
		}
		n := min(len(p)-written, s.credit, MaxForwardData)
		s.credit -= n
		s.mu.Unlock()
		if err := s.m.send(FwdMsg{Type: FwdData, ID: s.id, Data: p[written : written+n]}); err != nil {
			return written, err
		}
		written += n
	}
	return written, nil
}

// CloseWrite sends eof once: this side writes no more.
func (s *ForwardStream) CloseWrite() error {
	s.mu.Lock()
	if s.wclosed || s.closed || s.peerClosed {
		s.mu.Unlock()
		return nil
	}
	s.wclosed = true
	s.cond.Broadcast()
	s.mu.Unlock()
	return s.m.send(FwdMsg{Type: FwdEOF, ID: s.id})
}

// Close ends the stream both ways and tells the peer, unless the peer closed
// it first.
func (s *ForwardStream) Close() error {
	s.mu.Lock()
	tell := !s.peerClosed && !s.closed
	s.closed, s.buf = true, nil
	s.cond.Broadcast()
	s.mu.Unlock()
	s.m.mu.Lock()
	if s.m.streams[s.id] == s {
		delete(s.m.streams, s.id)
	}
	s.m.mu.Unlock()
	if tell {
		return s.m.send(FwdMsg{Type: FwdClose, ID: s.id})
	}
	return nil
}

package session

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"time"
)

// The resumable connection layer runs below SSH, so every channel survives a
// stream that drops (agent/docs/PROTOCOL.md "Resumable connections"). Each
// side sends frames `uvarint ack | uvarint len | data`: ack is the count of
// bytes received since the last ack it sent, data at most resumeMaxFrame
// bytes. A side keeps every byte it wrote until the peer acks it, so a resume
// on a new stream resends from the peer's received position.
const (
	resumeMaxFrame   = 128 << 10
	resumeSendBuffer = 2 << 20
	// The reader reads no further frame while resumeRecvBuffer bytes wait to
	// be read, so at most resumeRecvBuffer-1+resumeMaxFrame bytes wait.
	resumeRecvBuffer = 128 << 10
	// closeTag in the ack position is a deliberate close: the sender wrote
	// everything it had and the conn is over, so the peer ends instead of
	// waiting for a resume. No real ack reaches it.
	closeTag uint64 = math.MaxUint64
	// closeLinger bounds the wait for the peer to close its end after a
	// closeTag.
	closeLinger = 2 * time.Second
)

// ErrResumeLost ends a conn whose peer resumed from a position outside the
// send buffer: bytes it needs are gone. A malformed frame only drops the
// stream, like a cut one.
var ErrResumeLost = errors.New("resumable connection: resume position outside the send buffer")

// AttachEnd is how one attached stream ended.
type AttachEnd int

const (
	// Detached: the stream failed or was detached; the conn waits for a resume.
	Detached AttachEnd = iota
	// Closed: a deliberate close, sent or received.
	Closed
	// Ended: the conn ended (End, or a resume from a lost position).
	Ended
)

// ResumableConn is the net.Conn SSH runs on. Its bytes travel over one
// attached stream at a time; between streams Write buffers up to
// resumeSendBuffer and then blocks, and Read waits. Close is a deliberate
// close (flushed, then closeTag); End drops the conn at once.
type ResumableConn struct {
	mu   sync.Mutex
	cond *sync.Cond

	// send holds the written bytes from position sendStart the peer has not
	// acked; sent is the position the attached stream has written up to.
	send      []byte
	sendStart uint64
	sent      uint64
	// recv holds the received bytes not yet read; received counts every byte
	// received, acked the received position the peer was last told.
	recv     []byte
	received uint64
	acked    uint64

	localClosed  bool
	remoteClosed bool
	closeSent    bool
	ended        error

	att *attachment
}

// attachment is one attached stream. broken is guarded by the conn's mu; it
// is set once either loop is done or Detach runs.
type attachment struct {
	stream net.Conn
	broken bool
	done   chan struct{}
}

// NewResumableConn returns a detached conn at position 0 both ways.
func NewResumableConn() *ResumableConn {
	c := &ResumableConn{}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func (c *ResumableConn) sendEnd() uint64 { return c.sendStart + uint64(len(c.send)) }

// Received is the count of bytes received, the position a resume tells the
// peer. Read it only while the conn is detached.
func (c *ResumableConn) Received() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.received
}

// CanResumeFrom reports whether a peer that received peerReceived bytes can
// resume: every byte after it is still in the send buffer.
func (c *ResumableConn) CanResumeFrom(peerReceived uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ended == nil && peerReceived >= c.sendStart && peerReceived <= c.sendEnd()
}

// Resumable reports whether the conn can take a resume: not ended, and no
// deliberate close sent or received.
func (c *ResumableConn) Resumable() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ended == nil && !c.remoteClosed && !c.localClosed
}

// Attached reports whether a stream is attached.
func (c *ResumableConn) Attached() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.att != nil
}

// Attach is Install then the stream's run: it runs the conn over stream
// until the stream ends and reports how, closing stream before it returns.
func (c *ResumableConn) Attach(stream net.Conn, peerReceived uint64) AttachEnd {
	run, end := c.Install(stream, peerReceived)
	if run == nil {
		return end
	}
	return run()
}

// Install makes stream the conn's stream in one critical section: a stream
// still attached is detached first, and Install waits under the conn lock
// until its run is done, so the newest stream always takes over and no two
// run at once. peerReceived is the position the peer reported in the
// prelude, and the peer was told Received(). A position outside the send
// buffer ends the conn with ErrResumeLost and sends closeTag; an ended conn,
// or one whose peer closed it, refuses the stream; both close stream and return a nil run and Ended. The
// caller must call a non-nil run, once: it serves the stream until it ends
// (see Attach).
func (c *ResumableConn) Install(stream net.Conn, peerReceived uint64) (run func() AttachEnd, end AttachEnd) {
	c.mu.Lock()
	for c.att != nil && c.ended == nil {
		old := c.att
		old.broken = true
		_ = old.stream.Close()
		c.cond.Broadcast()
		for c.att == old {
			c.cond.Wait()
		}
	}
	switch {
	case c.ended != nil, c.remoteClosed:
		c.mu.Unlock()
		_ = stream.Close()
		return nil, Ended
	case peerReceived < c.sendStart || peerReceived > c.sendEnd():
		c.ended = ErrResumeLost
		c.cond.Broadcast()
		c.mu.Unlock()
		_, _ = stream.Write(binary.AppendUvarint(nil, closeTag))
		_ = stream.Close()
		return nil, Ended
	}
	c.trimLocked(peerReceived - c.sendStart)
	c.sent = peerReceived
	c.acked = c.received
	att := &attachment{stream: stream, done: make(chan struct{})}
	c.att = att
	c.mu.Unlock()
	return func() AttachEnd { return c.run(att) }, Detached
}

// run serves att's stream until it ends; see Attach.
func (c *ResumableConn) run(att *attachment) AttachEnd {
	stream := att.stream
	read := make(chan struct{})
	go func() {
		defer close(read)
		c.readLoop(att)
	}()
	c.writeLoop(att)
	c.mu.Lock()
	linger := c.closeSent
	c.mu.Unlock()
	if linger {
		// The peer closes its end on the closeTag. Closing first, with its
		// acks unread, would reset the stream and could drop the tag.
		select {
		case <-read:
		case <-time.After(closeLinger):
		}
	}
	_ = stream.Close()
	<-read

	c.mu.Lock()
	defer c.mu.Unlock()
	c.att = nil
	close(att.done)
	c.cond.Broadcast()
	switch {
	case c.ended != nil:
		return Ended
	case c.remoteClosed || c.closeSent:
		return Closed
	}
	return Detached
}

// Detach drops the attached stream, if any, and waits until its Attach is
// done, so the positions are settled for a resume.
func (c *ResumableConn) Detach() {
	c.mu.Lock()
	att := c.att
	if att == nil {
		c.mu.Unlock()
		return
	}
	att.broken = true
	c.cond.Broadcast()
	c.mu.Unlock()
	_ = att.stream.Close()
	<-att.done
}

// Done is closed once no stream is attached: at once while detached, else
// when the attached stream's Attach returns.
func (c *ResumableConn) Done() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.att == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	return c.att.done
}

// End drops the conn: Read and Write return err, and the attached stream is
// closed without a closeTag. The first End's err stays.
func (c *ResumableConn) End(err error) {
	c.mu.Lock()
	if c.ended == nil {
		c.ended = err
	}
	att := c.att
	c.cond.Broadcast()
	c.mu.Unlock()
	if att != nil {
		_ = att.stream.Close()
	}
}

// Ended returns the error End or a lost resume ended the conn with, or nil.
func (c *ResumableConn) Ended() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ended
}

// trimLocked drops n acked bytes from the front of the send buffer.
func (c *ResumableConn) trimLocked(n uint64) {
	if n == 0 {
		return
	}
	c.send = c.send[n:]
	c.sendStart += n
	if len(c.send) == 0 {
		c.send = nil
	}
	c.cond.Broadcast()
}

func (c *ResumableConn) readLoop(att *attachment) {
	defer func() {
		c.mu.Lock()
		att.broken = true
		c.cond.Broadcast()
		c.mu.Unlock()
	}()
	br := bufio.NewReaderSize(att.stream, 32<<10)
	buf := make([]byte, resumeMaxFrame)
	for {
		ack, err := binary.ReadUvarint(br)
		if err != nil {
			return
		}
		if ack == closeTag {
			c.mu.Lock()
			c.remoteClosed = true
			c.mu.Unlock()
			return
		}
		n, err := binary.ReadUvarint(br)
		if err != nil || n > resumeMaxFrame {
			return
		}
		c.mu.Lock()
		if ack > c.sent-c.sendStart {
			// An ack of bytes never sent on this stream: a broken peer or
			// relay. Drop the stream; the resume prelude settles positions.
			c.mu.Unlock()
			return
		}
		c.trimLocked(ack)
		for len(c.recv) >= resumeRecvBuffer && !att.broken && c.ended == nil && !c.localClosed {
			c.cond.Wait()
		}
		stop, discard := att.broken || c.ended != nil, c.localClosed
		c.mu.Unlock()
		if stop {
			return
		}
		if discard {
			// Closed here: drain until the peer closes, never read again.
			if _, err := br.Discard(int(n)); err != nil {
				return
			}
			continue
		}
		if n == 0 {
			continue
		}
		if _, err := io.ReadFull(br, buf[:n]); err != nil {
			return
		}
		c.mu.Lock()
		c.recv = append(c.recv, buf[:n]...)
		c.received += n
		c.cond.Broadcast()
		c.mu.Unlock()
	}
}

func (c *ResumableConn) writeLoop(att *attachment) {
	buf := make([]byte, 0, 2*binary.MaxVarintLen64+resumeMaxFrame)
	c.mu.Lock()
	for {
		for {
			if att.broken || c.ended != nil || c.remoteClosed {
				c.mu.Unlock()
				return
			}
			if c.sent < c.sendEnd() || c.received > c.acked {
				break
			}
			if c.localClosed {
				c.closeSent = true
				c.mu.Unlock()
				_, _ = att.stream.Write(binary.AppendUvarint(buf[:0], closeTag))
				return
			}
			c.cond.Wait()
		}
		ack := c.received - c.acked
		off := c.sent - c.sendStart
		n := min(c.sendEnd()-c.sent, resumeMaxFrame)
		buf = binary.AppendUvarint(buf[:0], ack)
		buf = binary.AppendUvarint(buf, n)
		buf = append(buf, c.send[off:off+n]...)
		c.acked += ack
		c.sent += n
		c.mu.Unlock()
		if _, err := att.stream.Write(buf); err != nil {
			c.mu.Lock()
			att.broken = true
			c.cond.Broadcast()
			c.mu.Unlock()
			return
		}
		c.mu.Lock()
	}
}

// Read returns received bytes, waiting across detached periods. It returns
// io.EOF after the peer's deliberate close.
func (c *ResumableConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.recv) == 0 {
		switch {
		case c.ended != nil:
			return 0, c.ended
		case c.localClosed:
			return 0, net.ErrClosed
		case c.remoteClosed:
			return 0, io.EOF
		}
		c.cond.Wait()
	}
	n := copy(p, c.recv)
	c.recv = c.recv[n:]
	if len(c.recv) == 0 {
		c.recv = nil
	}
	c.cond.Broadcast()
	return n, nil
}

// Write buffers p for sending. While the send buffer holds resumeSendBuffer
// unacked bytes it blocks until acks free space or the conn closes or ends;
// nothing is dropped.
func (c *ResumableConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	written := 0
	for len(p) > 0 {
		switch {
		case c.ended != nil:
			return written, c.ended
		case c.localClosed:
			return written, net.ErrClosed
		case c.remoteClosed:
			return written, io.ErrClosedPipe
		}
		room := resumeSendBuffer - len(c.send)
		if room <= 0 {
			c.cond.Wait()
			continue
		}
		k := min(room, len(p))
		c.send = append(c.send, p[:k]...)
		p = p[k:]
		written += k
		c.cond.Broadcast()
	}
	return written, nil
}

// CloseRemote records a deliberate close the peer sent outside a stream (a
// close resume), as a received closeTag: Read returns io.EOF once the
// received bytes are read, Write fails and Install refuses later streams.
func (c *ResumableConn) CloseRemote() {
	c.mu.Lock()
	c.remoteClosed = true
	c.cond.Broadcast()
	c.mu.Unlock()
}

// Close is a deliberate close: the attached stream sends what is buffered,
// then closeTag. A detached conn sends nothing; its owner ends it.
func (c *ResumableConn) Close() error {
	c.mu.Lock()
	c.localClosed = true
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}

type resumableAddr struct{}

func (resumableAddr) Network() string { return "resumable" }
func (resumableAddr) String() string  { return "session" }

func (c *ResumableConn) LocalAddr() net.Addr  { return resumableAddr{} }
func (c *ResumableConn) RemoteAddr() net.Addr { return resumableAddr{} }

// SSH sets no deadlines on a conn it did not dial; the owner bounds the
// handshake with End.
func (c *ResumableConn) SetDeadline(time.Time) error      { return errors.ErrUnsupported }
func (c *ResumableConn) SetReadDeadline(time.Time) error  { return errors.ErrUnsupported }
func (c *ResumableConn) SetWriteDeadline(time.Time) error { return errors.ErrUnsupported }

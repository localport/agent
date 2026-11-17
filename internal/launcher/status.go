package launcher

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// The status relay: the device service opens one KindStatus connection and
// sends status frames on it, each a 4-byte big-endian length and an opaque
// document of at most MaxStatusFrame bytes. The launcher keeps only the
// latest frame, never parses it, and writes it whole to each status reader,
// then closes. The frame is dropped when the publishing connection closes,
// so a stopped device service reads as no document.
const (
	// MaxStatusFrame bounds one status document, on the wire, in the
	// launcher and in a reader.
	MaxStatusFrame = 64 << 10
	// maxStatusReaders bounds the status readers served at once; an excess
	// connection is closed at accept.
	maxStatusReaders = 8
	// statusWriteTimeout bounds the write of one document to a reader.
	statusWriteTimeout = 2 * time.Second
)

// ErrStatusFrame refuses a status frame that is empty or over
// MaxStatusFrame; the publisher is disconnected.
var ErrStatusFrame = errors.New("status frame size out of range")

// statusRelay holds the publisher slot and the latest frame.
type statusRelay struct {
	mu        sync.Mutex
	publisher bool
	latest    []byte

	readers atomic.Int32
}

// claim takes the one publisher slot; false while another publisher is open.
func (r *statusRelay) claim() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.publisher {
		return false
	}
	r.publisher = true
	return true
}

// release frees the publisher slot and drops its frame.
func (r *statusRelay) release() {
	r.mu.Lock()
	r.publisher, r.latest = false, nil
	r.mu.Unlock()
}

func (r *statusRelay) set(frame []byte) {
	r.mu.Lock()
	r.latest = frame
	r.mu.Unlock()
}

// frame returns the latest frame, nil without a publisher. Frames are never
// modified after set.
func (r *statusRelay) frame() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.latest
}

// relay reads frames from the publisher into r until the connection fails or
// a frame is out of range.
func (r *statusRelay) relay(conn io.Reader) error {
	for {
		frame, err := readStatusFrame(conn)
		if err != nil {
			return err
		}
		r.set(frame)
	}
}

// enterReader counts a reader in; false when maxStatusReaders are served.
func (r *statusRelay) enterReader() bool {
	if r.readers.Add(1) > maxStatusReaders {
		r.readers.Add(-1)
		return false
	}
	return true
}

func (r *statusRelay) leaveReader() { r.readers.Add(-1) }

// writeTo writes the latest frame to an authorized reader under
// statusWriteTimeout; nothing when no publisher is connected.
func (r *statusRelay) writeTo(conn interface {
	io.Writer
	SetWriteDeadline(time.Time) error
}) error {
	frame := r.frame()
	if frame == nil {
		return nil
	}
	if err := conn.SetWriteDeadline(time.Now().Add(statusWriteTimeout)); err != nil {
		return err
	}
	_, err := conn.Write(frame)
	return err
}

// WriteStatusFrame sends one status document on a publishing connection.
func WriteStatusFrame(w io.Writer, doc []byte) error {
	if len(doc) == 0 || len(doc) > MaxStatusFrame {
		return fmt.Errorf("%w: %d bytes", ErrStatusFrame, len(doc))
	}
	buf := make([]byte, 4+len(doc))
	binary.BigEndian.PutUint32(buf, uint32(len(doc)))
	copy(buf[4:], doc)
	_, err := w.Write(buf)
	return err
}

func readStatusFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxStatusFrame {
		return nil, fmt.Errorf("%w: %d bytes", ErrStatusFrame, n)
	}
	frame := make([]byte, n)
	if _, err := io.ReadFull(r, frame); err != nil {
		return nil, err
	}
	return frame, nil
}

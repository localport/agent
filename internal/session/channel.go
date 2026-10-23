package session

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// MaxPlaintext is the largest plaintext one record carries.
const MaxPlaintext = 64 << 10

const (
	keySize = chacha20poly1305.KeySize
	// recordHeader is the uint32 big-endian sealed length before each record.
	recordHeader = 4
	maxSealed    = MaxPlaintext + chacha20poly1305.Overhead
)

// Channel seals and opens session records over a transport:
// uint32 length || ChaCha20-Poly1305(key, 0^32 || uint64 counter, plaintext),
// with an independent counter per direction starting at 0. The counter is
// implicit, so a dropped, replayed or reordered record fails authentication.
//
// Any read failure (authentication, oversize, transport end) is sticky: every
// later read returns the same error and the owner closes the transport. A
// transport end, clean or mid-record, is CodeTruncated; the rest are
// CodeProtocolError. A failed transport write is sticky for writes.
//
// Once a close record is sealed, every later write returns ErrChannelClosed,
// so no record follows close whichever goroutine writes.
//
// One goroutine may read while others write; writes are serialized. Each
// direction owns one buffer sized for the largest record, reused for every
// record.
type Channel struct {
	rw io.ReadWriter

	in direction

	outMu sync.Mutex
	out   direction
	// closed is set, under outMu, once a close record is sealed.
	closed bool
}

// ErrChannelClosed is returned by every write after this side sealed close.
var ErrChannelClosed = errors.New("session channel closed")

type direction struct {
	aead  cipher.AEAD
	seq   uint64
	nonce [chacha20poly1305.NonceSize]byte
	buf   []byte
	err   error
}

// AgentChannel is the agent's channel: it sends with A2C and receives with C2A.
func (k Keys) AgentChannel(rw io.ReadWriter) (*Channel, error) {
	return newChannel(rw, k.A2C, k.C2A)
}

// ClientChannel is the client's channel: it sends with C2A and receives with A2C.
func (k Keys) ClientChannel(rw io.ReadWriter) (*Channel, error) {
	return newChannel(rw, k.C2A, k.A2C)
}

func newChannel(rw io.ReadWriter, sendKey, recvKey []byte) (*Channel, error) {
	send, err := chacha20poly1305.New(sendKey)
	if err != nil {
		return nil, fmt.Errorf("send key: %w", err)
	}
	recv, err := chacha20poly1305.New(recvKey)
	if err != nil {
		return nil, fmt.Errorf("receive key: %w", err)
	}
	return &Channel{
		rw:  rw,
		in:  direction{aead: recv, buf: make([]byte, recordHeader+maxSealed)},
		out: direction{aead: send, buf: make([]byte, recordHeader+maxSealed)},
	}, nil
}

// nextNonce returns the nonce for the direction's current counter and
// advances it. A session ends long before 2^64 records, so reaching the last
// counter is refused rather than wrapped.
func (d *direction) nextNonce() ([]byte, error) {
	if d.seq == math.MaxUint64 {
		return nil, fail(CodeProtocolError, "record counter exhausted")
	}
	binary.BigEndian.PutUint64(d.nonce[4:], d.seq)
	d.seq++
	return d.nonce[:], nil
}

// writeRecord seals typ || body as one record and writes it in one Write.
func (c *Channel) writeRecord(typ byte, body []byte) error {
	c.outMu.Lock()
	defer c.outMu.Unlock()
	d := &c.out
	if c.closed {
		return ErrChannelClosed
	}
	if d.err != nil {
		return d.err
	}
	if 1+len(body) > MaxPlaintext {
		return fail(CodeProtocolError, fmt.Sprintf("message of %d bytes exceeds the record maximum", 1+len(body)))
	}
	nonce, err := d.nextNonce()
	if err != nil {
		d.err = err
		return err
	}
	plain := d.buf[recordHeader : recordHeader+1+len(body)]
	plain[0] = typ
	copy(plain[1:], body)
	sealed := d.aead.Seal(plain[:0], nonce, plain, nil)
	if typ == byte(TypeClose) {
		c.closed = true
	}
	binary.BigEndian.PutUint32(d.buf, uint32(len(sealed)))
	if _, err := c.rw.Write(d.buf[:recordHeader+len(sealed)]); err != nil {
		d.err = fmt.Errorf("write record: %w", err)
		return d.err
	}
	return nil
}

// readRecord reads and opens the next record. The plaintext aliases the read
// buffer and is valid until the next read.
func (c *Channel) readRecord() ([]byte, error) {
	d := &c.in
	if d.err != nil {
		return nil, d.err
	}
	if _, err := io.ReadFull(c.rw, d.buf[:recordHeader]); err != nil {
		return nil, d.close(&Error{Code: CodeTruncated, Detail: "transport ended before close", Err: err})
	}
	n := int(binary.BigEndian.Uint32(d.buf[:recordHeader]))
	if n > maxSealed {
		return nil, d.close(fail(CodeProtocolError, fmt.Sprintf("record of %d bytes exceeds the maximum", n)))
	}
	if n < chacha20poly1305.Overhead {
		return nil, d.close(fail(CodeProtocolError, "record shorter than its tag"))
	}
	sealed := d.buf[recordHeader : recordHeader+n]
	if _, err := io.ReadFull(c.rw, sealed); err != nil {
		return nil, d.close(&Error{Code: CodeTruncated, Detail: "transport ended inside a record", Err: err})
	}
	nonce, err := d.nextNonce()
	if err != nil {
		return nil, d.close(err)
	}
	plain, err := d.aead.Open(sealed[:0], nonce, sealed, nil)
	if err != nil {
		return nil, d.close(fail(CodeProtocolError, "record fails authentication"))
	}
	return plain, nil
}

// close makes err the direction's sticky error and returns it.
func (d *direction) close(err error) error {
	d.err = err
	return err
}

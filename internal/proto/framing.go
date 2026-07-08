package proto

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Frame layout on the wire:
//
//	+--------+------+----------------+
//	| length |  T   |    payload     |
//	|   4    |  1   |     N-1        |
//	+--------+------+----------------+
//
// length is big-endian and counts the type byte plus payload.

// defaultWriteTimeout bounds every framed control write. A peer that stops
// draining (dead link, zero receive window after a network change) would
// otherwise block the write (and, under wmu, every other send) for the
// kernel's multi-minute retransmission timeout. Control frames are tiny, so
// any write that can't finish in this window means the session is over.
const defaultWriteTimeout = 10 * time.Second

// Conn wraps a net.Conn with framed JSON messages. Sends and receives are
// independently serialized so the wrapper is safe for one writer and one
// reader running concurrently.
type Conn struct {
	raw          net.Conn
	wmu          sync.Mutex
	rmu          sync.Mutex
	hdrBuf       [5]byte
	writeTimeout time.Duration
}

func NewConn(c net.Conn) *Conn { return &Conn{raw: c, writeTimeout: defaultWriteTimeout} }

func (c *Conn) Underlying() net.Conn              { return c.raw }
func (c *Conn) Close() error                      { return c.raw.Close() }
func (c *Conn) SetReadDeadline(t time.Time) error { return c.raw.SetReadDeadline(t) }

// Send marshals payload (when non-nil) and writes a single framed message.
func (c *Conn) Send(t MessageType, payload any) error {
	var body []byte
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("proto: marshal %s: %w", t, err)
		}
		body = b
	}

	total := uint32(1 + len(body))
	if total > MaxMessageSize {
		return fmt.Errorf("proto: frame too large: %d > %d", total, MaxMessageSize)
	}

	c.wmu.Lock()
	defer c.wmu.Unlock()

	// Bound the write so a stuck socket can't wedge this and every queued
	// sender behind wmu. Cleared after: the data path reuses raw for io.Copy
	// once ConnectionReady is sent, which must run without a write deadline.
	if c.writeTimeout > 0 {
		_ = c.raw.SetWriteDeadline(time.Now().Add(c.writeTimeout))
		defer c.raw.SetWriteDeadline(time.Time{})
	}

	binary.BigEndian.PutUint32(c.hdrBuf[:4], total)
	c.hdrBuf[4] = byte(t)
	if _, err := c.raw.Write(c.hdrBuf[:]); err != nil {
		return fmt.Errorf("proto: write header: %w", err)
	}
	if len(body) > 0 {
		if _, err := c.raw.Write(body); err != nil {
			return fmt.Errorf("proto: write body: %w", err)
		}
	}
	return nil
}

// Recv reads one framed message and returns its type and raw JSON payload.
func (c *Conn) Recv() (MessageType, []byte, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()

	var hdr [5]byte
	if _, err := io.ReadFull(c.raw, hdr[:]); err != nil {
		return 0, nil, err
	}
	total := binary.BigEndian.Uint32(hdr[:4])
	if total == 0 {
		return 0, nil, errors.New("proto: zero-length frame")
	}
	if total > MaxMessageSize {
		return 0, nil, fmt.Errorf("proto: frame too large: %d", total)
	}

	t := MessageType(hdr[4])
	bodyLen := total - 1
	if bodyLen == 0 {
		return t, nil, nil
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(c.raw, body); err != nil {
		return 0, nil, fmt.Errorf("proto: read body: %w", err)
	}
	return t, body, nil
}

// Typed send helpers, these are the only ones the agent emits today.

func (c *Conn) SendRegister(p *RegisterPayload) error { return c.Send(MsgRegister, p) }
func (c *Conn) SendConnectionReady(p *ConnectionReadyPayload) error {
	return c.Send(MsgConnectionReady, p)
}
func (c *Conn) SendHeartbeat() error {
	return c.Send(MsgHeartbeat, &HeartbeatPayload{Timestamp: time.Now().Unix()})
}
func (c *Conn) SendHeartbeatAck(ts int64) error {
	return c.Send(MsgHeartbeatAck, &HeartbeatAckPayload{Timestamp: ts})
}
func (c *Conn) SendShutdown(reason string) error {
	return c.Send(MsgShutdown, &ShutdownPayload{Reason: reason})
}

// Payload parsers. Each one validates the JSON and returns a typed payload.

func ParseRegisterAck(b []byte) (*RegisterAckPayload, error) { return parse[RegisterAckPayload](b) }
func ParseNewConnection(b []byte) (*NewConnectionPayload, error) {
	return parse[NewConnectionPayload](b)
}
func ParseHeartbeat(b []byte) (*HeartbeatPayload, error) { return parse[HeartbeatPayload](b) }
func ParseSetActive(b []byte) (*SetActivePayload, error) { return parse[SetActivePayload](b) }
func ParseShutdown(b []byte) (*ShutdownPayload, error) {
	if len(b) == 0 {
		return &ShutdownPayload{}, nil
	}
	return parse[ShutdownPayload](b)
}
func ParseError(b []byte) (*ErrorPayload, error)       { return parse[ErrorPayload](b) }
func ParseRedirect(b []byte) (*RedirectPayload, error) { return parse[RedirectPayload](b) }

func parse[T any](b []byte) (*T, error) {
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

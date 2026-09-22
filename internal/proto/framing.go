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

	"github.com/localport/agent/internal/security"
)

// sanitize strips control and invisible formatting characters from wire
// values.
func sanitize(s string) string { return security.SanitizeDisplay(s) }

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

// maxRetainedWriteBuffer bounds the send buffer kept between frames. A larger
// buffer is released after use.
const maxRetainedWriteBuffer = 4 << 10

// Conn wraps a net.Conn with framed JSON messages. Sends and receives are
// serialized separately, so one reader and several writers may run
// concurrently.
type Conn struct {
	raw net.Conn
	wmu sync.Mutex
	rmu sync.Mutex
	// wbuf holds a whole frame for a single Write. Guarded by wmu.
	wbuf         []byte
	writeTimeout time.Duration
}

func NewConn(c net.Conn) *Conn { return &Conn{raw: c, writeTimeout: defaultWriteTimeout} }

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

	// Check the size before narrowing, which could truncate it.
	size := len(body) + 1
	if size > MaxMessageSize {
		return fmt.Errorf("proto: frame too large: %d > %d", size, MaxMessageSize)
	}
	total := uint32(size)

	c.wmu.Lock()
	defer c.wmu.Unlock()

	// The deadline keeps a stuck socket from blocking every sender behind wmu.
	// It is cleared afterwards because the data path reuses raw for io.Copy
	// after ConnectionReady.
	if c.writeTimeout > 0 {
		_ = c.raw.SetWriteDeadline(time.Now().Add(c.writeTimeout))
		defer func() { _ = c.raw.SetWriteDeadline(time.Time{}) }()
	}

	// Write header and body in one call. Separate writes cost two TLS records,
	// and a partial frame desyncs the peer.
	c.wbuf = binary.BigEndian.AppendUint32(c.wbuf[:0], total)
	c.wbuf = append(c.wbuf, byte(t))
	c.wbuf = append(c.wbuf, body...)

	if _, err := c.raw.Write(c.wbuf); err != nil {
		return fmt.Errorf("proto: write frame %s: %w", t, err)
	}
	if cap(c.wbuf) > maxRetainedWriteBuffer {
		c.wbuf = nil
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
func (c *Conn) SendMuxBind(p *MuxBindPayload) error { return c.Send(MsgMuxBind, p) }
func (c *Conn) SendPortsAck(p *PortsAckPayload) error {
	return c.Send(MsgPortsAck, p)
}

// Payload parsers validate the JSON, strip control characters from displayed
// fields and return a typed payload. They are the sanitization boundary for
// inbound strings.
//
// These fields are matched or dialed, so they stay verbatim.
//
//   - SessionID, compared byte for byte by the edge on resume.
//   - TunnelID, EdgeID.
//   - EdgeAddr, a dial target checked by allowedRedirectHost.
//   - ConnectionID, echoed in ConnectionReady and sanitized for display in
//     ui.shortID.

func ParseRegisterAck(b []byte) (*RegisterAckPayload, error) {
	p, err := parse[RegisterAckPayload](b)
	if err != nil {
		return nil, err
	}
	p.TunnelName = sanitize(p.TunnelName)
	p.Region = sanitize(p.Region)
	p.RegionName = sanitize(p.RegionName)
	p.PublicURL = sanitize(p.PublicURL)
	for i := range p.URLs {
		p.URLs[i] = sanitize(p.URLs[i])
	}
	p.Subdomain = sanitize(p.Subdomain)
	p.Mode = sanitize(p.Mode)
	p.Protocol = sanitize(p.Protocol)
	p.Error = sanitize(p.Error)
	p.ErrorCode = sanitize(p.ErrorCode)
	p.LimitType = LimitType(sanitize(string(p.LimitType)))
	for i := range p.Ports {
		p.Ports[i].Protocol = sanitize(p.Ports[i].Protocol)
	}
	return p, nil
}

func ParseMuxBindAck(b []byte) (*MuxBindAckPayload, error) {
	p, err := parse[MuxBindAckPayload](b)
	if err != nil {
		return nil, err
	}
	p.Error = sanitize(p.Error)
	p.Code = sanitize(p.Code)
	return p, nil
}

func ParseNewConnection(b []byte) (*NewConnectionPayload, error) {
	p, err := parse[NewConnectionPayload](b)
	if err != nil {
		return nil, err
	}
	p.RemoteAddr = sanitize(p.RemoteAddr)
	p.TargetProtocol = sanitize(p.TargetProtocol)
	p.Consumer = sanitize(p.Consumer)
	return p, nil
}

func ParsePortsUpdate(b []byte) (*PortsUpdatePayload, error) {
	p, err := parse[PortsUpdatePayload](b)
	if err != nil {
		return nil, err
	}
	for i := range p.Ports {
		p.Ports[i].Protocol = sanitize(p.Ports[i].Protocol)
	}
	return p, nil
}

func ParseHeartbeat(b []byte) (*HeartbeatPayload, error) { return parse[HeartbeatPayload](b) }

func ParseShutdown(b []byte) (*ShutdownPayload, error) {
	if len(b) == 0 {
		return &ShutdownPayload{}, nil
	}
	p, err := parse[ShutdownPayload](b)
	if err != nil {
		return nil, err
	}
	p.Reason = sanitize(p.Reason)
	p.Code = sanitize(p.Code)
	p.LimitType = LimitType(sanitize(string(p.LimitType)))
	return p, nil
}

func ParseError(b []byte) (*ErrorPayload, error) {
	p, err := parse[ErrorPayload](b)
	if err != nil {
		return nil, err
	}
	p.Code = sanitize(p.Code)
	p.Message = sanitize(p.Message)
	return p, nil
}

func ParseRedirect(b []byte) (*RedirectPayload, error) {
	p, err := parse[RedirectPayload](b)
	if err != nil {
		return nil, err
	}
	p.Reason = sanitize(p.Reason)
	return p, nil
}

func parse[T any](b []byte) (*T, error) {
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

package launcher

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Forward messages ride the session channel of a forward request after the
// launcher's start answer: the agent asks the networking helper (the forward
// server, running as the login) to dial or listen, and the helper answers and
// reports each connection a listener accepts. Every message is a 1-byte type,
// a 4-byte big-endian payload length and a payload whose layout and bounds
// the type fixes; a message outside them fails decoding, which ends the
// helper.
//
// The agent allocates even ids (dial, listen) and the helper odd ids
// (accepted); each side's ids strictly increase, so none is reused within a
// connection. On Linux and macOS an ok for a dial and every accepted carry
// the connected socket as SCM_RIGHTS on the same channel; on Windows no
// descriptor crosses and each forward's bytes ride the channel as data, eof,
// window and close messages under a credit window (ForwardMux).
const (
	FwdDial     byte = 1
	FwdListen   byte = 2
	FwdClose    byte = 3
	FwdOK       byte = 4
	FwdRefused  byte = 5
	FwdAccepted byte = 6
	FwdData     byte = 7
	FwdEOF      byte = 8
	FwdWindow   byte = 9
)

// Forward networks.
const (
	FwdTCP  byte = 1
	FwdUnix byte = 2
)

// Bounds of forward messages.
const (
	// MaxForwardHost bounds a dial host and an accepted origin host.
	MaxForwardHost = 255
	// MaxForwardPath bounds a unix socket path: sun_path is 104 bytes on
	// macOS, the smaller of the two platforms.
	MaxForwardPath = 104
	// MaxForwardData bounds one data message's bytes.
	MaxForwardData = 32 << 10
	// ForwardWindow is the credit each side grants per forward and
	// direction: the bytes a sender may have in flight unacknowledged.
	ForwardWindow = 64 << 10
	// maxForwardPayload is the largest payload of any type: a data message.
	maxForwardPayload = 4 + MaxForwardData
)

// Refusal codes of a forward, in a refused message.
const (
	FwdCodeConnectionRefused byte = 1
	FwdCodeUnreachable       byte = 2
	FwdCodePermissionDenied  byte = 3
	FwdCodeAddressInUse      byte = 4
	FwdCodePathExists        byte = 5
	FwdCodeUnsupported       byte = 6
	FwdCodeInvalid           byte = 7
	FwdCodeLimit             byte = 8
)

var fwdCodeNames = map[byte]string{
	FwdCodeConnectionRefused: "connection_refused",
	FwdCodeUnreachable:       "unreachable",
	FwdCodePermissionDenied:  "permission_denied",
	FwdCodeAddressInUse:      "address_in_use",
	FwdCodePathExists:        "path_exists",
	FwdCodeUnsupported:       "unsupported",
	FwdCodeInvalid:           "invalid",
	FwdCodeLimit:             "limit",
}

// FwdCodeName is the wire name of a refusal code, "" for an unknown one.
func FwdCodeName(code byte) string { return fwdCodeNames[code] }

// FwdMsg is one decoded forward message. Which fields a type uses:
//
//	dial      ID (even), Network, Host and Port (tcp, port 1-65535) or Path (unix)
//	listen    ID (even), Network, Port (tcp, 0-65535) and IPv6 (bind ::1, else 127.0.0.1) or Path (unix)
//	close     ID
//	ok        ID (even), Port (the bound port of a tcp listen, else 0)
//	refused   ID (even), Code
//	accepted  ListenerID (even), ID (odd), Host and Port (the origin; empty and 0 for unix)
//	data      ID, Data (1 to MaxForwardData bytes)
//	eof       ID
//	window    ID, N (1 to ForwardWindow)
//
// A decoded message's Data is valid until the next read on the same reader.
type FwdMsg struct {
	Type       byte
	ID         uint32
	ListenerID uint32
	Network    byte
	Host       string
	Port       uint16
	IPv6       bool
	Path       string
	Code       byte
	Data       []byte
	N          uint32
}

// errBadForward is a forward message no peer of this protocol sends.
var errBadForward = errors.New("launcher: bad forward message")

func validForwardHost(h string, allowEmpty bool) bool {
	if h == "" {
		return allowEmpty
	}
	return len(h) <= MaxForwardHost && !strings.ContainsRune(h, 0)
}

// ValidForwardPath reports whether p is a unix socket path a forward may
// name: absolute, 1 to MaxForwardPath bytes, no NUL.
func ValidForwardPath(p string) bool {
	return len(p) <= MaxForwardPath && strings.HasPrefix(p, "/") && !strings.ContainsRune(p, 0)
}

// validate checks m against its type's bounds.
func (m FwdMsg) validate() error {
	even := m.ID%2 == 0
	ok := false
	switch m.Type {
	case FwdDial:
		switch m.Network {
		case FwdTCP:
			ok = even && validForwardHost(m.Host, false) && m.Port != 0
		case FwdUnix:
			ok = even && ValidForwardPath(m.Path)
		}
	case FwdListen:
		switch m.Network {
		case FwdTCP:
			ok = even
		case FwdUnix:
			ok = even && ValidForwardPath(m.Path)
		}
	case FwdClose, FwdEOF:
		ok = true
	case FwdOK:
		ok = even
	case FwdRefused:
		ok = even && fwdCodeNames[m.Code] != ""
	case FwdAccepted:
		ok = m.ListenerID%2 == 0 && !even && validForwardHost(m.Host, true)
	case FwdData:
		ok = len(m.Data) >= 1 && len(m.Data) <= MaxForwardData
	case FwdWindow:
		ok = m.N >= 1 && m.N <= ForwardWindow
	}
	if !ok {
		return errBadForward
	}
	return nil
}

// AppendForwardMsg appends m's encoding to b; a message outside its type's
// bounds is refused.
func AppendForwardMsg(b []byte, m FwdMsg) ([]byte, error) {
	if err := m.validate(); err != nil {
		return b, err
	}
	start := len(b)
	b = append(b, m.Type, 0, 0, 0, 0)
	switch m.Type {
	case FwdAccepted:
		b = binary.BigEndian.AppendUint32(b, m.ListenerID)
	}
	b = binary.BigEndian.AppendUint32(b, m.ID)
	switch m.Type {
	case FwdDial, FwdListen:
		b = append(b, m.Network)
		switch {
		case m.Network == FwdUnix:
			b = append(b, m.Path...)
		case m.Type == FwdDial:
			b = binary.BigEndian.AppendUint16(b, m.Port)
			b = append(b, m.Host...)
		default:
			b = binary.BigEndian.AppendUint16(b, m.Port)
			fam := byte(4)
			if m.IPv6 {
				fam = 6
			}
			b = append(b, fam)
		}
	case FwdOK:
		b = binary.BigEndian.AppendUint16(b, m.Port)
	case FwdRefused:
		b = append(b, m.Code)
	case FwdAccepted:
		b = binary.BigEndian.AppendUint16(b, m.Port)
		b = append(b, m.Host...)
	case FwdData:
		b = append(b, m.Data...)
	case FwdWindow:
		b = binary.BigEndian.AppendUint32(b, m.N)
	}
	binary.BigEndian.PutUint32(b[start+1:], uint32(len(b)-start-frameHeader))
	return b, nil
}

// ForwardReader decodes forward messages from a byte stream into one reused
// buffer.
type ForwardReader struct {
	r   io.Reader
	buf []byte
}

// NewForwardReader returns a reader over r.
func NewForwardReader(r io.Reader) *ForwardReader {
	return &ForwardReader{r: r, buf: make([]byte, maxForwardPayload)}
}

// Read reads one message. It returns io.EOF only at a message boundary.
func (fr *ForwardReader) Read() (FwdMsg, error) {
	var hdr [frameHeader]byte
	if _, err := io.ReadFull(fr.r, hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return FwdMsg{}, fmt.Errorf("%w: truncated header", errBadForward)
		}
		return FwdMsg{}, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > maxForwardPayload {
		return FwdMsg{}, errBadForward
	}
	p := fr.buf[:n]
	if _, err := io.ReadFull(fr.r, p); err != nil {
		return FwdMsg{}, fmt.Errorf("%w: truncated payload", errBadForward)
	}
	return parseForwardMsg(hdr[0], p)
}

// parseForwardMsg decodes one payload of type typ; every byte must belong to
// a field.
func parseForwardMsg(typ byte, p []byte) (FwdMsg, error) {
	m := FwdMsg{Type: typ}
	u32 := func() (uint32, bool) {
		if len(p) < 4 {
			return 0, false
		}
		v := binary.BigEndian.Uint32(p)
		p = p[4:]
		return v, true
	}
	u16 := func() (uint16, bool) {
		if len(p) < 2 {
			return 0, false
		}
		v := binary.BigEndian.Uint16(p)
		p = p[2:]
		return v, true
	}
	ok := true
	if typ == FwdAccepted {
		m.ListenerID, ok = u32()
	}
	if ok {
		m.ID, ok = u32()
	}
	if !ok {
		return FwdMsg{}, errBadForward
	}
	switch typ {
	case FwdDial, FwdListen:
		if len(p) < 1 {
			return FwdMsg{}, errBadForward
		}
		m.Network, p = p[0], p[1:]
		switch {
		case m.Network == FwdUnix:
			m.Path, p = string(p), nil
		case m.Network != FwdTCP:
			ok = false
		case typ == FwdDial:
			m.Port, ok = u16()
			m.Host, p = string(p), nil
		default:
			m.Port, ok = u16()
			if ok && len(p) == 1 && (p[0] == 4 || p[0] == 6) {
				m.IPv6, p = p[0] == 6, nil
			} else {
				ok = false
			}
		}
	case FwdClose, FwdEOF:
	case FwdOK:
		m.Port, ok = u16()
	case FwdRefused:
		if len(p) == 1 {
			m.Code, p = p[0], nil
		} else {
			ok = false
		}
	case FwdAccepted:
		m.Port, ok = u16()
		m.Host, p = string(p), nil
	case FwdData:
		m.Data, p = p, nil
	case FwdWindow:
		ok = len(p) == 4
		if ok {
			m.N, p = binary.BigEndian.Uint32(p), nil
		}
	default:
		ok = false
	}
	if !ok || len(p) != 0 {
		return FwdMsg{}, errBadForward
	}
	if err := m.validate(); err != nil {
		return FwdMsg{}, err
	}
	return m, nil
}

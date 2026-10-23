package session

import (
	"encoding/json"
	"fmt"
)

// MessageType is the first plaintext byte of every record.
type MessageType byte

// Envelope types shared by every kind. Types 0x04 to 0x0f are unassigned and
// refused; a kind defines its own types from TypeKindBase up.
const (
	// TypeClose ends the session; its body is JSON {"reason": "..."}.
	TypeClose MessageType = 0x00
	// TypeStart is the client's first message; its body is the kind's JSON.
	TypeStart MessageType = 0x01
	// TypeData carries raw kind bytes.
	TypeData MessageType = 0x02
	// TypeActivity has an empty body and marks the session as in use.
	TypeActivity MessageType = 0x03
	// TypeKindBase is the first type a kind defines for itself.
	TypeKindBase MessageType = 0x10
)

// Terminal kind types. A terminal session refuses every other kind type.
const (
	// TypeResize (client to agent) carries JSON {"cols", "rows"}.
	TypeResize MessageType = TypeKindBase
	// TypeExit (agent to client) carries JSON {"code"}: the exit status of
	// the spawned process, or 128 plus the signal number.
	TypeExit MessageType = TypeKindBase + 1
)

// MaxBody is the largest message body one record carries.
const MaxBody = MaxPlaintext - 1

// Message is one received envelope.
type Message struct {
	Type MessageType
	// Body aliases the channel's read buffer and is valid until the next
	// ReadMessage.
	Body []byte
	// Reason is the close reason when Type is TypeClose.
	Reason string
}

type closeBody struct {
	Reason string `json:"reason"`
}

// ReadMessage reads the next record and checks its envelope. An empty record,
// an unassigned type, a close without a reason or an activity with a body is
// CodeProtocolError and, like every read failure, closes the read side. A
// transport end is CodeTruncated: the peer never sent close, so in-flight work
// is failed.
func (c *Channel) ReadMessage() (Message, error) {
	plain, err := c.readRecord()
	if err != nil {
		return Message{}, err
	}
	if len(plain) == 0 {
		return Message{}, c.in.close(fail(CodeProtocolError, "empty record"))
	}
	m := Message{Type: MessageType(plain[0]), Body: plain[1:]}
	switch {
	case m.Type == TypeClose:
		var body closeBody
		if json.Unmarshal(m.Body, &body) != nil || body.Reason == "" {
			return Message{}, c.in.close(fail(CodeProtocolError, "close without a reason"))
		}
		m.Reason = body.Reason
	case m.Type == TypeActivity:
		if len(m.Body) != 0 {
			return Message{}, c.in.close(fail(CodeProtocolError, "activity with a body"))
		}
	case m.Type == TypeStart, m.Type == TypeData, m.Type >= TypeKindBase:
	default:
		return Message{}, c.in.close(fail(CodeProtocolError, fmt.Sprintf("unknown message type 0x%02x", byte(m.Type))))
	}
	return m, nil
}

// WriteMessage seals one message of type t. body is at most MaxBody bytes.
func (c *Channel) WriteMessage(t MessageType, body []byte) error {
	return c.writeRecord(byte(t), body)
}

// WriteClose sends the close message that ends the session from this side.
func (c *Channel) WriteClose(reason string) error {
	body, err := json.Marshal(closeBody{Reason: reason})
	if err != nil {
		return fmt.Errorf("encode close: %w", err)
	}
	return c.writeRecord(byte(TypeClose), body)
}

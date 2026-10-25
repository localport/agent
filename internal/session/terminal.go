package session

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

const (
	// maxTerminalOutput bounds the PTY output one data record carries.
	maxTerminalOutput = 16 << 10
	// maxTerminalSize bounds cols and rows.
	maxTerminalSize = 1000
	defaultTerm     = "xterm-256color"
)

var termPattern = regexp.MustCompile(`^[a-zA-Z0-9.+-]{1,32}$`)

// terminalSize is a window size in character cells.
type terminalSize struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
}

func (z terminalSize) valid() bool {
	return z.Cols >= 1 && z.Cols <= maxTerminalSize && z.Rows >= 1 && z.Rows <= maxTerminalSize
}

// terminalStart is a terminal session's start body.
type terminalStart struct {
	terminalSize
	Term string
}

// terminalInput is one client record after start: data for the PTY, or a
// new window size.
type terminalInput struct {
	data   []byte
	resize *terminalSize
}

// parseTerminalStart parses a start body {cols, rows, term}. term defaults to
// xterm-256color. Any other field, a size out of 1 to 1000 or a bad term is
// a protocol error.
func parseTerminalStart(body []byte) (terminalStart, error) {
	var b struct {
		Cols int     `json:"cols"`
		Rows int     `json:"rows"`
		Term *string `json:"term"`
	}
	if err := decodeStrict(body, &b); err != nil {
		return terminalStart{}, fail(CodeProtocolError, "start: "+err.Error())
	}
	st := terminalStart{terminalSize: terminalSize{Cols: b.Cols, Rows: b.Rows}, Term: defaultTerm}
	if !st.valid() {
		return terminalStart{}, fail(CodeProtocolError, "start: cols and rows must be 1 to 1000")
	}
	if b.Term != nil {
		if !termPattern.MatchString(*b.Term) {
			return terminalStart{}, fail(CodeProtocolError, "start: bad term")
		}
		st.Term = *b.Term
	}
	return st, nil
}

// decodeTerminalInput decodes a client record after start. Types other than
// data and resize are a protocol error.
func decodeTerminalInput(m Message) (terminalInput, error) {
	switch m.Type {
	case TypeData:
		return terminalInput{data: m.Body}, nil
	case TypeResize:
		var z terminalSize
		if err := decodeStrict(m.Body, &z); err != nil {
			return terminalInput{}, fail(CodeProtocolError, "resize: "+err.Error())
		}
		if !z.valid() {
			return terminalInput{}, fail(CodeProtocolError, "resize: cols and rows must be 1 to 1000")
		}
		return terminalInput{resize: &z}, nil
	}
	return terminalInput{}, fail(CodeProtocolError, "terminal: unexpected record type")
}

// exitBody encodes an exit record's body.
func exitBody(code int) []byte {
	b, _ := json.Marshal(struct {
		Code int `json:"code"`
	}{code})
	return b
}

// decodeStrict decodes one JSON value into v, refusing unknown fields and
// trailing data.
func decodeStrict(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the JSON value")
	}
	return nil
}

package launcher

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Frame types on the session channel between the agent and the helper. The
// agent sends data, resize and eof (end of the session's input); the helper
// sends data, stderr (an exec session's standard error without a PTY), event
// (one file operation of an sftp session, a FileEvent in JSON) and exit, and
// exit is its last frame.
const (
	FrameData   byte = 1
	FrameResize byte = 2
	FrameExit   byte = 3
	FrameStderr byte = 4
	FrameEOF    byte = 5
	FrameEvent  byte = 6
)

// MaxFrameData bounds a data frame's payload; MaxFrameEvent an event frame's,
// which fits a FileEvent whose Path and Target are each maxEventPath bytes
// doubled by JSON escaping.
const (
	MaxFrameData  = 64 << 10
	MaxFrameEvent = 20 << 10
)

// Frame is one decoded channel frame. Data is valid until the next
// ReadFrame on the same reader.
type Frame struct {
	Type       byte
	Data       []byte
	Cols, Rows uint16
	Code       int32
}

const frameHeader = 5

// errBadFrame is a frame no peer of this protocol sends.
var errBadFrame = errors.New("launcher: bad channel frame")

// WriteFrame writes one frame. The caller serializes writers.
func WriteFrame(w io.Writer, f Frame) error {
	var payload []byte
	switch f.Type {
	case FrameData, FrameStderr:
		if len(f.Data) == 0 || len(f.Data) > MaxFrameData {
			return errBadFrame
		}
		payload = f.Data
	case FrameEvent:
		if len(f.Data) == 0 || len(f.Data) > MaxFrameEvent {
			return errBadFrame
		}
		payload = f.Data
	case FrameEOF:
	case FrameResize:
		payload = binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(nil, f.Cols), f.Rows)
	case FrameExit:
		payload = binary.BigEndian.AppendUint32(nil, uint32(f.Code))
	default:
		return errBadFrame
	}
	buf := make([]byte, frameHeader, frameHeader+len(payload))
	buf[0] = f.Type
	binary.BigEndian.PutUint32(buf[1:], uint32(len(payload)))
	_, err := w.Write(append(buf, payload...))
	return err
}

// FrameReader reads frames into one reused buffer.
type FrameReader struct {
	r   io.Reader
	buf []byte
}

// NewFrameReader returns a reader over r.
func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{r: r, buf: make([]byte, MaxFrameData)}
}

// ReadFrame reads one frame. It returns io.EOF only at a frame boundary.
func (fr *FrameReader) ReadFrame() (Frame, error) {
	var hdr [frameHeader]byte
	if _, err := io.ReadFull(fr.r, hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return Frame{}, fmt.Errorf("%w: truncated header", errBadFrame)
		}
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	f := Frame{Type: hdr[0]}
	switch f.Type {
	case FrameData, FrameStderr:
		if n == 0 || n > MaxFrameData {
			return Frame{}, errBadFrame
		}
	case FrameEvent:
		if n == 0 || n > MaxFrameEvent {
			return Frame{}, errBadFrame
		}
	case FrameEOF:
		if n != 0 {
			return Frame{}, errBadFrame
		}
	case FrameResize, FrameExit:
		if n != 4 {
			return Frame{}, errBadFrame
		}
	default:
		return Frame{}, errBadFrame
	}
	p := fr.buf[:n]
	if _, err := io.ReadFull(fr.r, p); err != nil {
		return Frame{}, fmt.Errorf("%w: truncated payload", errBadFrame)
	}
	switch f.Type {
	case FrameData, FrameStderr, FrameEvent:
		f.Data = p
	case FrameResize:
		f.Cols, f.Rows = binary.BigEndian.Uint16(p), binary.BigEndian.Uint16(p[2:])
		if f.Cols < 1 || f.Cols > maxTerminalSize || f.Rows < 1 || f.Rows > maxTerminalSize {
			return Frame{}, errBadFrame
		}
	case FrameExit:
		f.Code = int32(binary.BigEndian.Uint32(p))
	}
	return f, nil
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

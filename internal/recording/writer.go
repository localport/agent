package recording

import (
	"bytes"
	"encoding/json"
	"strconv"
	"time"
	"unicode/utf8"
)

// MaxLine is the largest event line the Writer emits, newline included. It
// leaves room for the header so a segment holding the header and one line
// never exceeds MaxPlaintext.
const MaxLine = MaxPlaintext - 128

// Writer encodes a session channel as asciicast v3 lines. It records output,
// resize, exit, marker, files-log ("f") and port forward ("p") events only;
// input has no entry point. Event times come from the caller, so tests drive it
// with a fake clock. A Writer is not safe for concurrent use.
type Writer struct {
	start      time.Time
	cols, rows uint16
	// emittedMs is the sum of every interval written so far. Each interval
	// is the rounded real elapsed time minus this sum, so rounding errors do
	// not accumulate (error diffusion).
	emittedMs int64
	// partial holds the bytes of a UTF-8 sequence cut at the end of the last
	// Output, joined to the next one.
	partial []byte
}

// NewWriter returns a Writer for a session that started at start with a
// terminal of cols x rows.
func NewWriter(start time.Time, cols, rows uint16) *Writer {
	return &Writer{start: start, cols: cols, rows: rows}
}

// Header returns the asciicast v3 header line that opens segment 0.
func (w *Writer) Header() []byte {
	b := []byte(`{"version":3,"term":{"cols":`)
	b = strconv.AppendUint(b, uint64(w.cols), 10)
	b = append(b, `,"rows":`...)
	b = strconv.AppendUint(b, uint64(w.rows), 10)
	b = append(b, `},"timestamp":`...)
	b = strconv.AppendInt(b, w.start.Unix(), 10)
	return append(b, "}\n"...)
}

// Output returns the "o" lines for data written to the terminal at at.
// Invalid UTF-8 becomes U+FFFD; a sequence cut at the end of data is held
// for the next call. Data whose line would exceed MaxLine is split into
// several events, the later ones with interval 0. It returns nil when every
// byte is held.
func (w *Writer) Output(at time.Time, data []byte) [][]byte {
	if len(w.partial) > 0 {
		data = append(w.partial, data...)
		w.partial = nil
	}
	if cut := incompleteTail(data); cut < len(data) {
		w.partial = append([]byte(nil), data[cut:]...)
		data = data[:cut]
	}
	if len(data) == 0 {
		return nil
	}
	return w.outputLines(nil, w.interval(at), data)
}

// Flush returns an "o" line for a held partial UTF-8 sequence (as U+FFFD),
// or nil when none is held. Call it when the session ends without an exit.
func (w *Writer) Flush(at time.Time) []byte {
	if len(w.partial) == 0 {
		return nil
	}
	data := w.partial
	w.partial = nil
	return eventLine(w.interval(at), 'o', jsonString(data))
}

// Resize returns the "r" line for a terminal resized to cols x rows.
func (w *Writer) Resize(at time.Time, cols, rows uint16) []byte {
	size := strconv.AppendUint(nil, uint64(cols), 10)
	size = append(size, 'x')
	size = strconv.AppendUint(size, uint64(rows), 10)
	return eventLine(w.interval(at), 'r', jsonString(size))
}

// Exit returns the held partial sequence line, if any, and the "x" line for
// a shell that exited with status.
func (w *Writer) Exit(at time.Time, status uint32) [][]byte {
	var lines [][]byte
	if l := w.Flush(at); l != nil {
		lines = append(lines, l)
	}
	return append(lines, eventLine(w.interval(at), 'x', jsonString(strconv.AppendUint(nil, uint64(status), 10))))
}

// File returns the "f" line of one files-log event at at: an asciicast v3
// extension event whose data is the event's JSON object as a string. The
// caller passes a validated event (launcher.FileEvent); players that do not
// know the code skip it, as asciicast v3 requires.
func (w *Writer) File(at time.Time, event []byte) []byte {
	return eventLine(w.interval(at), 'f', jsonString(event))
}

// Forward returns the "p" line of one port forward event at at: an asciicast
// v3 extension event whose data is the event's JSON object as a string. The
// caller passes a validated event; forwarded bytes are never recorded.
func (w *Writer) Forward(at time.Time, event []byte) []byte {
	return eventLine(w.interval(at), 'p', jsonString(event))
}

// Marker returns the "m" line of an asciicast v3 marker labelled label: the
// session recorder marks a connection's detach and attach with it.
func (w *Writer) Marker(at time.Time, label string) []byte {
	return eventLine(w.interval(at), 'm', jsonString([]byte(label)))
}

// interval returns the milliseconds to write for an event at at. A clock
// that steps back yields 0 and the deficit is absorbed by later events.
func (w *Writer) interval(at time.Time) int64 {
	elapsed := at.Sub(w.start).Round(time.Millisecond).Milliseconds()
	d := elapsed - w.emittedMs
	if d < 0 {
		return 0
	}
	w.emittedMs = elapsed
	return d
}

// outputLines appends the "o" lines for data, halving it at a rune boundary
// until each line fits MaxLine.
func (w *Writer) outputLines(lines [][]byte, ms int64, data []byte) [][]byte {
	line := eventLine(ms, 'o', jsonString(data))
	if len(line) <= MaxLine || len(data) < 2 {
		return append(lines, line)
	}
	mid := len(data) / 2
	for i := mid; i > 0 && i > mid-utf8.UTFMax; i-- {
		if utf8.RuneStart(data[i]) {
			mid = i
			break
		}
	}
	lines = w.outputLines(lines, ms, data[:mid])
	return w.outputLines(lines, 0, data[mid:])
}

// incompleteTail returns the index where a valid but unfinished UTF-8
// sequence at the end of b starts, or len(b) when b ends on a whole rune or
// on bytes that can never form one.
func incompleteTail(b []byte) int {
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax+1; i-- {
		if utf8.RuneStart(b[i]) {
			if !utf8.FullRune(b[i:]) {
				return i
			}
			break
		}
	}
	return len(b)
}

// eventLine formats [interval, "code", data] with the interval in seconds at
// millisecond precision.
func eventLine(ms int64, code byte, jsonData []byte) []byte {
	b := make([]byte, 0, len(jsonData)+24)
	b = append(b, '[')
	b = strconv.AppendInt(b, ms/1000, 10)
	b = append(b, '.')
	frac := ms % 1000
	if frac < 100 {
		b = append(b, '0')
	}
	if frac < 10 {
		b = append(b, '0')
	}
	b = strconv.AppendInt(b, frac, 10)
	b = append(b, ',', '"', code, '"', ',')
	b = append(b, jsonData...)
	return append(b, ']', '\n')
}

// jsonString returns b as a JSON string with each invalid UTF-8 byte
// replaced by U+FFFD.
func jsonString(b []byte) []byte {
	valid := make([]byte, 0, len(b))
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		if r == utf8.RuneError && n == 1 {
			valid = utf8.AppendRune(valid, utf8.RuneError)
		} else {
			valid = append(valid, b[:n]...)
		}
		b = b[n:]
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	// Encoding a string cannot fail.
	_ = enc.Encode(string(valid))
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

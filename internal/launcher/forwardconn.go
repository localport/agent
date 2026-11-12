package launcher

import (
	"fmt"
	"io"
	"os"
)

// frameForwardTransport carries forward messages inside the data frames of a
// piped helper session (Windows): the helper relays the forward server's
// standard input and output as it relays any command's, so the message
// stream is the concatenation of the data frames. The server's stderr is
// logged; its exit frame ends the stream.
type frameForwardTransport struct {
	ch   io.ReadWriteCloser
	fr   *FrameReader
	rest []byte
	log  func(string, ...any)
	// logged counts the stderr bytes seen; past maxForwardLogBytes one notice
	// is logged (logCut) and the rest dropped.
	logged int
	logCut bool
}

// maxForwardLogBytes bounds what one forward server may write to the
// agent's log, as the Unix helper bounds it (sessionhelper maxChildLogBytes).
const maxForwardLogBytes = 64 << 10

func newFrameForwardTransport(ch io.ReadWriteCloser, log func(string, ...any)) *frameForwardTransport {
	return &frameForwardTransport{ch: ch, fr: NewFrameReader(ch), log: log}
}

func (t *frameForwardTransport) Read(p []byte) (int, error) {
	for len(t.rest) == 0 {
		f, err := t.fr.ReadFrame()
		if err != nil {
			return 0, err
		}
		switch f.Type {
		case FrameData:
			t.rest = f.Data
		case FrameStderr:
			// The forward server runs as the login: its text is quoted, so it
			// cannot forge log lines, and bounded per session.
			switch {
			case t.logged < maxForwardLogBytes:
				t.log("launcher: forward helper: %q", f.Data)
			case !t.logCut:
				t.logCut = true
				t.log("launcher: forward helper: output over %d bytes dropped", maxForwardLogBytes)
			}
			t.logged += len(f.Data)
		case FrameExit:
			return 0, io.EOF
		default:
			return 0, fmt.Errorf("%w: frame %d on a forward channel", errBadForward, f.Type)
		}
	}
	n := copy(p, t.rest)
	t.rest = t.rest[n:]
	return n, nil
}

// writeMsg writes one whole message as one data frame; ForwardClient.send
// serializes its callers.
func (t *frameForwardTransport) writeMsg(b []byte) error {
	return WriteFrame(t.ch, Frame{Type: FrameData, Data: b})
}

func (t *frameForwardTransport) takeFD() *os.File { return nil }
func (t *frameForwardTransport) passesFDs() bool  { return false }
func (t *frameForwardTransport) Close() error     { return t.ch.Close() }

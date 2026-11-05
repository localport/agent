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
}

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
			t.log("launcher: forward helper: %s", f.Data)
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

package launcher

import (
	"errors"
	"fmt"
	"io"
)

// ErrUnavailable means the launcher socket could not be reached or the
// launcher ended the connection before answering.
var ErrUnavailable = errors.New("launcher unavailable")

// Session is a started session's request connection. Its exit report is
// secondary: the helper's exit frame on the channel is the session's exit.
type Session struct {
	conn io.ReadWriteCloser
	ID   string
}

// Wait reads the launcher's exit report of the helper. It fails when the
// launcher restarted or ended the connection first.
func (s *Session) Wait() (Exit, error) {
	resp, err := readResponse(s.conn)
	if err != nil {
		return Exit{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if resp.Exit == nil {
		return Exit{}, errors.New("launcher: unexpected response after start")
	}
	return *resp.Exit, nil
}

// Close ends the request connection; the session goes on.
func (s *Session) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

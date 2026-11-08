package launcher

import (
	"errors"
	"io"
)

// ErrUnavailable means the launcher socket could not be reached or the
// launcher ended the connection before answering.
var ErrUnavailable = errors.New("launcher unavailable")

// Session is a started session's request connection. The helper's exit frame
// on the channel is the session's exit; the launcher logs a helper that ended
// by a signal, and the agent does not read the launcher's exit report.
type Session struct {
	conn io.ReadWriteCloser
	ID   string
}

// Close ends the request connection; the session goes on.
func (s *Session) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

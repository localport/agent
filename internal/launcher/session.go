package launcher

import (
	"errors"
	"io"
)

// ErrUnavailable means the launcher socket could not be reached or the
// launcher ended the connection before answering.
var ErrUnavailable = errors.New("launcher unavailable")

// Session is a started session's request connection. The helper's exit frame
// on the channel is the session's exit, and its end frame the reason it ended
// the session; the launcher logs a helper that ended by a signal, and the
// agent does not read the launcher's exit report.
type Session struct {
	conn io.ReadWriteCloser
	ID   string
	// Messages are the PAM messages of the session's setup, for the client.
	Messages []string
	// FullDiskAccess is the launcher's reading taken for this session
	// (macOS); empty elsewhere.
	FullDiskAccess string
	// Confined, Home and WholeDisk are an sftp session's view
	// (launcher.Started); zero for every other kind.
	Confined  bool
	Home      string
	WholeDisk bool
}

// Close ends the request connection; the session goes on.
func (s *Session) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

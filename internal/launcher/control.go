package launcher

import (
	"errors"
	"fmt"
	"io"
	"time"
)

// The control endpoint of a foreground run. A privileged run that is not the
// device service (`localport run`, `localport up --foreground`) serves it, so
// `up`, `down` and `set` can make that run reload its config as the service
// manager's reload makes the service do. Only root (Unix) or SYSTEM and
// elevated Administrators (Windows) may connect. The exchange is one request,
// controlReload, answered by controlOK once the reload is queued, or by
// controlStarting while the run holds run.lock but has not yet read the config
// (it reads the change with it), or by controlRefused when the run cannot read
// the client's peer credentials (Unix). The holder of run.lock opens the
// endpoint right after taking the lock and keeps it until it releases the
// lock. On Unix root takes run.lock, opens the listening socket, answers
// controlStarting itself while it enrols, then passes the socket and the lock
// to the agent-account child that serves the devices (socket activation); a
// client that connects during the hand-off waits until the child accepts.
const (
	controlReload   = "reload\n"
	controlOK       = "ok\n"
	controlStarting = "starting\n"
	controlRefused  = "refused\n"
	// controlTimeout bounds the run's side of one exchange.
	controlTimeout = 2 * time.Second
)

var (
	// ErrNoForegroundRun means no foreground run serves the control endpoint:
	// it does not exist, a run that exited left it behind, or the run exited
	// before it answered.
	ErrNoForegroundRun = errors.New("no foreground run serves the control endpoint")
	// ErrRunStarting means a foreground run holds run.lock but has not yet
	// read the config: the change is in the config it reads, so it applies
	// when the run starts serving the devices.
	ErrRunStarting = errors.New("the foreground run is starting")
	// ErrControlRefused means a foreground run serves the control endpoint but
	// refused the request because it could not read the client's credentials.
	ErrControlRefused = errors.New("the foreground run refused the control request")
	// ErrControlUntrusted refuses a control endpoint that is not a foreground
	// run's: on Unix a link or non-socket, a socket not owned by root or open
	// to group or others, or a directory root does not own or group or others
	// may write; on Windows a pipe not owned by SYSTEM or Administrators, or one
	// whose DACL admits anyone else.
	ErrControlUntrusted = errors.New("the control endpoint is not a foreground run's")
	// ErrControlBusy means another process serves the control endpoint.
	ErrControlBusy = errors.New("another process serves the control endpoint")
)

// deadlineConn is a connection with deadlines: a Unix socket or a pollable
// pipe.
type deadlineConn interface {
	io.ReadWriter
	SetDeadline(time.Time) error
}

// answerControl reads one request from an authorized client and calls
// reload, which queues the reload and reports true, or reports false while the
// run has not yet read the config; it answers controlOK or controlStarting.
// Any other request is refused by closing without an answer.
func answerControl(conn deadlineConn, reload func() bool) error {
	if err := conn.SetDeadline(time.Now().Add(controlTimeout)); err != nil {
		return err
	}
	req := make([]byte, len(controlReload))
	if _, err := io.ReadFull(conn, req); err != nil {
		return err
	}
	if string(req) != controlReload {
		return fmt.Errorf("unknown control request %q", req)
	}
	answer := controlStarting
	if reload() {
		answer = controlOK
	}
	_, err := io.WriteString(conn, answer)
	return err
}

// refuseControl reads one request, then answers controlRefused. Closing before
// the request arrives fails the client's write with EPIPE, which the client
// reads as no run.
func refuseControl(conn deadlineConn) error {
	if err := conn.SetDeadline(time.Now().Add(controlTimeout)); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, make([]byte, len(controlReload))); err != nil {
		return err
	}
	_, err := io.WriteString(conn, controlRefused)
	return err
}

// askReload sends the reload request on conn and waits up to wait for the
// answer: nil for controlOK, ErrRunStarting for controlStarting,
// ErrControlRefused for controlRefused.
func askReload(conn deadlineConn, wait time.Duration) error {
	if err := conn.SetDeadline(time.Now().Add(wait)); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, controlReload); err != nil {
		return err
	}
	ans, err := readAnswer(conn)
	if err != nil {
		return fmt.Errorf("read the control answer: %w", err)
	}
	switch ans {
	case controlOK:
		return nil
	case controlStarting:
		return ErrRunStarting
	case controlRefused:
		return ErrControlRefused
	}
	return fmt.Errorf("unexpected control answer %q", ans)
}

// readAnswer reads one newline-terminated answer, no longer than the longest
// one. A connection closed before the newline is io.EOF or
// io.ErrUnexpectedEOF.
func readAnswer(r io.Reader) (string, error) {
	buf := make([]byte, 0, len(controlStarting))
	b := make([]byte, 1)
	for len(buf) < cap(buf) {
		if _, err := io.ReadFull(r, b); err != nil {
			if len(buf) > 0 && errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return "", err
		}
		buf = append(buf, b[0])
		if b[0] == '\n' {
			return string(buf), nil
		}
	}
	return "", fmt.Errorf("control answer %q is too long", buf)
}

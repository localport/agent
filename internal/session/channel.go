package session

import (
	"context"
	"errors"
	"io"
	"os"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/localport/agent/internal/launcher"
)

// Reasons a channel's start fails with, written to its stderr.
const (
	// CloseHelperFailed: the helper's channel ended without an exit frame.
	CloseHelperFailed = "helper_failed"
	// CloseLauncherUnavailable: the launcher could not be reached.
	CloseLauncherUnavailable = "launcher_unavailable"
	CodeLoginNotAllowed      = "login_not_allowed"
	CodeKindDisabled         = "kind_disabled"
	CodeAgentBusy            = "agent_busy"
	CodeKindUnavailable      = "kind_unavailable"
)

const (
	// maxTerminalSize bounds pty-req and window-change sizes.
	maxTerminalSize = 1000
	// defaultCols and defaultRows size the recording's cast of a channel
	// without a PTY.
	defaultCols, defaultRows = 80, 24
	// maxClientRead bounds one read of client bytes into one data frame.
	maxClientRead = 16 << 10
	// startTimeout bounds the launcher's start of a channel's session.
	startTimeout = 15 * time.Second
)

var termPattern = regexp.MustCompile(`^[a-zA-Z0-9.+-]{1,32}$`)

// afterChannelEnd, when set by a test, runs at the end of a channel's end, so
// a test can order an end before a launcher Start returns.
var afterChannelEnd atomic.Pointer[func()]

// ptyRequest is a pty-req's terminal (RFC 4254 6.2).
type ptyRequest struct {
	Term          string
	Cols, Rows    uint32
	Width, Height uint32
	Modes         string
}

// windowChange is a window-change's size (RFC 4254 6.7).
type windowChange struct {
	Cols, Rows    uint32
	Width, Height uint32
}

// channel is one session channel: its requests until a shell or exec starts
// a launcher session, then the relay between the channel and the helper:
// client bytes become data frames (and eof), the helper's data and stderr
// frames become channel data and extended data, and its exit frame becomes
// exit-status and the channel's close.
type channel struct {
	c  *conn
	ch ssh.Channel

	pty     *ptyRequest
	started bool
	// recording is set when this channel's output is the recording's cast.
	recording bool

	// mu orders start's hand-off of helper, session, started and readerDone
	// against end, which may run on another goroutine while the launcher
	// starts the session.
	mu      sync.Mutex
	helper  *os.File
	session *launcher.Session
	// wmu serializes frame writes to the helper.
	wmu sync.Mutex

	stopped atomic.Bool
	// halted is closed by end; it releases an output tap waiting on a full
	// Strict recording queue. Made with the channel.
	halted     chan struct{}
	endOnce    sync.Once
	readerDone chan struct{}
}

// serve handles the channel's requests until the channel closes, then ends
// the helper's session and joins the relay.
func (ch *channel) serve(reqs <-chan *ssh.Request) {
	for req := range reqs {
		ch.c.active()
		ok := ch.handle(req)
		if req.WantReply {
			_ = req.Reply(ok, nil)
		}
	}
	ch.end("")
	if ch.readerDone != nil {
		<-ch.readerDone
	}
	_ = ch.session.Close()
}

// handle applies one channel request and reports whether it succeeded. Agent
// forwarding, X11, subsystems, signals and env are refused.
func (ch *channel) handle(req *ssh.Request) bool {
	switch req.Type {
	case "pty-req":
		var p ptyRequest
		if ch.started || ch.pty != nil || ssh.Unmarshal(req.Payload, &p) != nil || !validSize(p.Cols, p.Rows) || !termPattern.MatchString(p.Term) {
			return false
		}
		ch.pty = &p
		return true
	case "window-change":
		var w windowChange
		if ch.pty == nil || ssh.Unmarshal(req.Payload, &w) != nil || !validSize(w.Cols, w.Rows) {
			return false
		}
		ch.pty.Cols, ch.pty.Rows = w.Cols, w.Rows
		if ch.started {
			if ch.writeFrame(launcher.Frame{Type: launcher.FrameResize, Cols: uint16(w.Cols), Rows: uint16(w.Rows)}) == nil && ch.recording {
				ch.c.rec.resize(uint16(w.Cols), uint16(w.Rows))
			}
		}
		return true
	case "shell":
		if ch.started {
			return false
		}
		if ch.pty != nil {
			return ch.start(launcher.KindTerminal, "")
		}
		// A shell without a terminal is a command session of the login shell.
		return ch.c.adm.Kind == "ssh" && ch.start(launcher.KindExec, "")
	case "exec":
		var e struct{ Command string }
		if ch.started || ch.c.adm.Kind != "ssh" || ssh.Unmarshal(req.Payload, &e) != nil ||
			len(e.Command) > launcher.MaxCommand {
			return false
		}
		return ch.start(launcher.KindExec, e.Command)
	}
	return false
}

func validSize(cols, rows uint32) bool {
	return cols >= 1 && cols <= maxTerminalSize && rows >= 1 && rows <= maxTerminalSize
}

// start asks the launcher for the channel's session and starts the relay. A
// refusal is written to the channel's stderr and fails the request.
func (ch *channel) start(kind, command string) bool {
	s := ch.c.s
	req := launcher.Request{Kind: kind, Device: s.cfg.Device, Login: ch.c.login, Command: command}
	cols, rows := uint16(defaultCols), uint16(defaultRows)
	if ch.pty != nil {
		req.Cols, req.Rows, req.Term = int(ch.pty.Cols), int(ch.pty.Rows), ch.pty.Term
		cols, rows = uint16(ch.pty.Cols), uint16(ch.pty.Rows)
	}
	ours, theirs, pipe, err := newSessionChannel()
	if err != nil {
		s.log("session: session channel: %v", err)
		ch.refuse(CodeKindUnavailable)
		return false
	}
	req.Pipe = pipe
	ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
	sess, err := s.launcher.Start(ctx, req, theirs)
	cancel()
	if theirs != nil {
		_ = theirs.Close()
	}
	if err != nil {
		_ = ours.Close()
		s.log("session: %s for %q did not start: %v", kind, ch.c.login, err)
		ch.refuse(refusalReason(err))
		return false
	}
	// end may have run while the launcher started the session (a client
	// disconnect, idle, Shutdown): it found no helper to close, so the new
	// session is ended here and never relayed.
	ch.mu.Lock()
	if ch.stopped.Load() {
		ch.mu.Unlock()
		_ = ours.Close()
		_ = sess.Close()
		return false
	}
	ch.helper, ch.session, ch.started = ours, sess, true
	ch.readerDone = make(chan struct{})
	ch.mu.Unlock()
	if ch.c.claimRecording() {
		ch.recording = true
		ch.c.rec.start(time.Now(), cols, rows)
	}
	go ch.readHelper()
	go ch.readClient()
	return true
}

// refuse tells the client why its request failed.
func (ch *channel) refuse(code string) {
	_, _ = ch.ch.Stderr().Write([]byte("localport: " + code + "\r\n"))
}

// refusalReason maps a launcher refusal to the code the client sees.
func refusalReason(err error) string {
	if errors.Is(err, launcher.ErrUnavailable) {
		return CloseLauncherUnavailable
	}
	switch launcher.CodeOf(err) {
	case launcher.CodeLoginNotEnabled, launcher.CodeAccountUnavailable, launcher.CodeAccountRefused:
		return CodeLoginNotAllowed
	case launcher.CodeKindNotEnabled, launcher.CodeUnsupportedKind:
		return CodeKindDisabled
	case launcher.CodeBusy:
		return CodeAgentBusy
	}
	return CodeKindUnavailable
}

func (ch *channel) writeFrame(f launcher.Frame) error {
	ch.wmu.Lock()
	defer ch.wmu.Unlock()
	return launcher.WriteFrame(ch.helper, f)
}

// readClient copies the client's bytes to data frames, and its EOF to an
// eof frame, until the channel or the helper ends.
func (ch *channel) readClient() {
	buf := make([]byte, maxClientRead)
	for {
		n, err := ch.ch.Read(buf)
		if n > 0 {
			ch.c.active()
			if ch.writeFrame(launcher.Frame{Type: launcher.FrameData, Data: buf[:n]}) != nil {
				return
			}
		}
		if errors.Is(err, io.EOF) {
			_ = ch.writeFrame(launcher.Frame{Type: launcher.FrameEOF})
			return
		}
		if err != nil {
			return
		}
	}
}

// readHelper relays the helper's frames until its exit frame or the
// channel's end.
func (ch *channel) readHelper() {
	defer close(ch.readerDone)
	fr := launcher.NewFrameReader(ch.helper)
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			if !ch.stopped.Load() {
				ch.c.s.log("session: the helper's channel ended without an exit: %v", err)
				ch.end(CloseHelperFailed)
			}
			return
		}
		switch f.Type {
		case launcher.FrameData, launcher.FrameStderr:
			if ch.recording {
				ch.c.rec.output(f.Data, ch.halted)
			}
			if ch.stopped.Load() {
				return
			}
			w := io.Writer(ch.ch)
			if f.Type == launcher.FrameStderr {
				w = ch.ch.Stderr()
			}
			if _, err := w.Write(f.Data); err != nil {
				return
			}
		case launcher.FrameExit:
			if ch.recording {
				ch.c.rec.exit(int(f.Code))
			}
			if !ch.stopped.Swap(true) {
				_, _ = ch.ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(f.Code)}))
				_ = ch.ch.CloseWrite()
				_ = ch.ch.Close()
			}
			return
		default:
			ch.c.s.log("session: unexpected frame %d from the helper", f.Type)
			ch.end(CloseHelperFailed)
			return
		}
	}
}

// end stops the relay once: it releases an output tap waiting on a full
// Strict recording queue, tells the client reason on its stderr when there is
// one, closes the helper's channel (the helper reads EOF and runs its end
// path) and closes the SSH channel.
func (ch *channel) end(reason string) {
	ch.endOnce.Do(func() {
		ch.mu.Lock()
		wasStopped := ch.stopped.Swap(true)
		helper := ch.helper
		ch.mu.Unlock()
		close(ch.halted)
		if reason != "" && !wasStopped {
			_, _ = ch.ch.Stderr().Write([]byte("\r\nlocalport: session ended: " + reason + "\r\n"))
		}
		if helper != nil {
			_ = helper.Close()
		}
		_ = ch.ch.Close()
		if hook := afterChannelEnd.Load(); hook != nil {
			(*hook)()
		}
	})
}

package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strconv"
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
	// CloseFilesNarrowed: a resume admitted the connection under a
	// certificate whose files@localport.io no longer allows what this SFTP
	// channel's file server was started with.
	CloseFilesNarrowed  = "files_narrowed"
	CodeLoginNotAllowed = "login_not_allowed"
	CodeKindDisabled    = "kind_disabled"
	CodeAgentBusy       = "agent_busy"
	CodeKindUnavailable = "kind_unavailable"
	// CodeRecordingUnavailable: a Strict channel whose recording could not
	// open is refused before its helper starts.
	CodeRecordingUnavailable = "recording_unavailable"
)

const (
	// maxTerminalSize bounds pty-req and window-change sizes.
	maxTerminalSize = 1000
	// defaultCols and defaultRows size the recording's cast of a channel
	// without a PTY.
	defaultCols, defaultRows = 80, 24
	// recordedNotice opens the stderr of every recorded shell or exec, the
	// native client's counterpart of the browser's recording notice.
	recordedNotice = "localport: this session is recorded\r\n"
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
// exit-status or exit-signal and the channel's close.
type channel struct {
	c  *conn
	ch ssh.Channel

	pty     *ptyRequest
	started bool
	// kind is the launcher kind start ran (terminal, exec or sftp).
	kind string
	// env holds the client's accepted env requests (launcher.ValidEnv).
	env map[string]string
	// rec is this channel's recording on a recorded connection, nil
	// otherwise; set by start before the relay goroutines, ended by serve.
	rec *sessionRecorder
	// recAttempted is set under mu once the start tried to record.
	recAttempted bool

	// mu orders start's hand-off of helper, session, started and readerDone
	// against end, which may run on another goroutine while the launcher
	// starts the session.
	mu      sync.Mutex
	helper  *os.File
	session *launcher.Session
	// files is the access an sftp channel's file server was started with.
	files filesAccess
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
	// After the reader's last tap.
	ch.rec.end()
}

// handle applies one channel request and reports whether it succeeded. env
// is accepted for LANG and LC_* only, before the shell or exec, within the
// launcher's bounds. A files connection serves the sftp subsystem only; an
// ssh connection serves it beside shells and commands. Agent forwarding,
// X11, other subsystems and signals are refused.
func (ch *channel) handle(req *ssh.Request) bool {
	// The kind is the same under every admission of a connection.
	kind := ch.c.adm.Load().Kind
	files := kind == "files"
	switch req.Type {
	case "subsystem":
		var s struct{ Name string }
		if ch.started || ssh.Unmarshal(req.Payload, &s) != nil || s.Name != "sftp" ||
			(kind != "ssh" && !files) {
			return false
		}
		return ch.start(launcher.KindSFTP, "")
	case "pty-req", "shell", "exec":
		if files {
			return false
		}
	}
	switch req.Type {
	case "env":
		var e struct{ Name, Value string }
		if ch.started || ssh.Unmarshal(req.Payload, &e) != nil {
			return false
		}
		next := maps.Clone(ch.env)
		if next == nil {
			next = map[string]string{}
		}
		next[e.Name] = e.Value
		if !launcher.ValidEnv(next) {
			return false
		}
		ch.env = next
		return true
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
			if ch.writeFrame(launcher.Frame{Type: launcher.FrameResize, Cols: uint16(w.Cols), Rows: uint16(w.Rows)}) == nil {
				ch.rec.resize(uint16(w.Cols), uint16(w.Rows))
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
		return kind == "ssh" && ch.start(launcher.KindExec, "")
	case "exec":
		var e struct{ Command string }
		if ch.started || kind != "ssh" || ssh.Unmarshal(req.Payload, &e) != nil ||
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

// start opens the channel's recording on a recorded connection, asks the
// launcher for the channel's session and starts the relay. A refusal is
// written to the channel's stderr and fails the request.
func (ch *channel) start(kind, command string) bool {
	s := ch.c.s
	req := launcher.Request{Kind: kind, Device: s.cfg.Device, Login: ch.c.login, Command: command, Env: ch.env}
	var files filesAccess
	if kind == launcher.KindSFTP {
		files = ch.c.adm.Load().Files
		req.FilesDownload, req.FilesUpload = files.Download, files.Upload
	}
	if len(ch.c.password) > 0 {
		// The launcher client zeroes its copy once sent.
		req.HasPassword, req.Password = true, bytes.Clone(ch.c.password)
	}
	cols, rows := uint16(defaultCols), uint16(defaultRows)
	if ch.pty != nil && kind != launcher.KindSFTP {
		req.Cols, req.Rows, req.Term = int(ch.pty.Cols), int(ch.pty.Rows), ch.pty.Term
		cols, rows = uint16(ch.pty.Cols), uint16(ch.pty.Rows)
	}
	rec, ok := ch.openRecording()
	if !ok {
		return false
	}
	ours, theirs, pipe, err := newSessionChannel()
	if err != nil {
		s.log("session: session channel: %v", err)
		rec.abort()
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
		rec.abort()
		s.log("session: %s for %q did not start: %v", kind, ch.c.login, err)
		ch.refuse(refusalReason(err))
		return false
	}
	// end may have run while the launcher started the session (a client
	// disconnect, idle, Shutdown): it found no helper to close, so the new
	// session is ended here and never relayed.
	ch.mu.Lock()
	// A resume that narrowed the file access while the server started either
	// finds ch.files set (conn.readmit ends the channel) or is seen here: the
	// admission is stored before readmit reads ch.files under ch.mu.
	current := ch.c.adm.Load()
	narrowed := kind == launcher.KindSFTP && !current.Files.covers(files)
	// The same stored-admission check as narrowed: a resume that named a
	// recording either finds ch.started set or is seen here.
	required := current.violatedBy(recordingStateOf(rec, ch.recAttempted))
	if ch.stopped.Load() || narrowed || required {
		ch.mu.Unlock()
		_ = ours.Close()
		_ = sess.Close()
		rec.abort()
		switch {
		case narrowed:
			ch.refuse(CloseFilesNarrowed)
		case required:
			ch.refuse(CloseRecordingRequired)
		}
		return false
	}
	ch.files = files
	ch.helper, ch.session, ch.started, ch.rec, ch.kind = ours, sess, true, rec, kind
	ch.readerDone = make(chan struct{})
	ch.mu.Unlock()
	rec.start(time.Now(), cols, rows)
	if kind == launcher.KindExec {
		// The command line is the files log's exec entry; "" is the login
		// shell on pipes. Validated by the exec request's bound.
		if ev, err := (launcher.FileEvent{Op: launcher.OpExec, Command: command}).Marshal(); err == nil {
			rec.file(ev, ch.halted)
		}
	}
	if rec != nil {
		if kind != launcher.KindSFTP {
			// Written before the helper's output is relayed, so it is the
			// first line the user sees; an sftp client shows no stderr.
			_, _ = ch.ch.Stderr().Write([]byte(recordedNotice))
		}
		go ch.watchRecording(rec)
	}
	go ch.readHelper()
	go ch.readClient()
	return true
}

// openRecording opens this channel's own recording when the certificate the
// connection runs under names one: a fresh recording id and that admission's
// session id.
// A Strict channel whose recording cannot open is refused (false), so no
// helper runs unrecorded; a Best effort one runs unrecorded (nil, true).
func (ch *channel) openRecording() (*sessionRecorder, bool) {
	c := ch.c
	a := c.adm.Load()
	if a.Rec == nil {
		return nil, true
	}
	ch.mu.Lock()
	ch.recAttempted = true
	ch.mu.Unlock()
	id := uuidText(newRecordingID())
	rec, err := c.s.startRecording(id, a.sessionID, a.admission, c.s.cfg.clock.Now(), a.recordedStarts.Add(1))
	if err == nil {
		return rec, true
	}
	if a.Rec.Policy == RecPolicyStrict {
		c.s.log("session: %s: channel refused: %v", a.sessionID, err)
		ch.refuse(CodeRecordingUnavailable)
		return nil, false
	}
	c.s.log("session: %s: channel runs unrecorded: %v", a.sessionID, err)
	return nil, true
}

// recordingViolated reports whether this channel, started and not stopped,
// cannot run under a; a channel with no start request has no state.
func (ch *channel) recordingViolated(a *connAdmission) bool {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	return ch.started && !ch.stopped.Load() && a.violatedBy(recordingStateOf(ch.rec, ch.recAttempted))
}

// watchRecording ends the channel when its Strict recording fails.
func (ch *channel) watchRecording(rec *sessionRecorder) {
	select {
	case <-rec.failedC():
		ch.end(CloseRecordingFailed)
	case <-ch.halted:
	}
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

// exitSignalMsg is the SSH exit-signal payload (RFC 4254 section 6.10).
type exitSignalMsg struct {
	Signal     string
	CoreDumped bool
	Error      string
	Lang       string
}

// rfcSignals are the signal names RFC 4254 section 6.10 defines.
var rfcSignals = []string{"ABRT", "ALRM", "FPE", "HUP", "ILL", "INT", "KILL", "PIPE", "QUIT", "SEGV", "TERM", "USR1", "USR2"}

// decodeExit reads an exit frame's code. Off Windows a negative code -n means
// killed by signal n, recorded as 128+n; on Windows the code is the process's
// 32-bit exit status, which may read negative.
func decodeExit(code int32, goos string) (status int, signal string) {
	if goos == "windows" || code >= 0 {
		return int(uint32(code)), ""
	}
	n := int(-code)
	name := signalName(n)
	if name == "" {
		name = strconv.Itoa(n)
	}
	if !slices.Contains(rfcSignals, name) {
		name += "@localport.io"
	}
	return 128 + n, name
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
			// An sftp channel's bytes are the protocol stream, file contents
			// included; its recording holds the file events only.
			if ch.kind != launcher.KindSFTP {
				ch.rec.output(f.Data, ch.halted)
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
		case launcher.FrameEvent:
			// Only an sftp helper reports file operations; a malformed or
			// misplaced event ends the channel.
			ev, err := launcher.ParseFileEvent(f.Data)
			if ch.kind != launcher.KindSFTP || err != nil || ev.Op == launcher.OpExec {
				ch.c.s.log("session: a bad file event from the helper")
				ch.end(CloseHelperFailed)
				return
			}
			line, _ := ev.Marshal()
			ch.rec.file(line, ch.halted)
		case launcher.FrameExit:
			status, signal := decodeExit(f.Code, runtime.GOOS)
			ch.rec.exit(status)
			if !ch.stopped.Swap(true) {
				if signal != "" {
					_, _ = ch.ch.SendRequest("exit-signal", false, ssh.Marshal(exitSignalMsg{Signal: signal}))
				} else {
					_, _ = ch.ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(status)}))
				}
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
		// Before the reason: its write can wait on a full send buffer.
		if helper != nil {
			_ = helper.Close()
		}
		if reason != "" && !wasStopped {
			_, _ = ch.ch.Stderr().Write([]byte("\r\nlocalport: session ended: " + reason + "\r\n"))
		}
		_ = ch.ch.Close()
		if hook := afterChannelEnd.Load(); hook != nil {
			(*hook)()
		}
	})
}

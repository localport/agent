//go:build linux || darwin

package session

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/localport/agent/internal/launcher"
)

// Agent close reasons of a terminal relayed through the launcher.
const (
	// CloseHelperFailed: the helper's channel ended without an exit frame.
	CloseHelperFailed = "helper_failed"
	// CloseLauncherUnavailable: the launcher could not be reached after the
	// ticket was spent.
	CloseLauncherUnavailable = "launcher_unavailable"
)

// probeTimeout bounds the launcher probe before the spend.
const probeTimeout = 2 * time.Second

// kindFor returns the session kind that serves kind, or nil when this build
// has none. Linux and macOS serve terminal, through l (the launcher socket
// when nil).
func kindFor(kind string, l Launcher) prepareKind {
	if kind != "terminal" {
		return nil
	}
	if l == nil {
		l = launcher.DefaultClient()
	}
	return func(device, login string, log func(string, ...any)) (newKind, error) {
		return prepareTerminal(l, device, log)
	}
}

// prepareTerminal probes the launcher before the spend, so a launcher that
// is down refuses the ticket unspent. The login and the account are checked
// by the launcher and its helper after the start record.
func prepareTerminal(l Launcher, device string, log func(string, ...any)) (newKind, error) {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	if _, err := l.Probe(ctx); err != nil {
		return nil, &Error{Code: CodeKindUnavailable, Detail: "terminal: the session launcher", Err: err}
	}
	return func(ch *Channel, start []byte, login string, rec *sessionRecorder) (kindSession, error) {
		st, err := parseTerminalStart(start)
		if err != nil {
			return nil, err
		}
		rec.start(time.Now(), uint16(st.Cols), uint16(st.Rows))
		return startRelay(l, ch, device, login, st, log, rec), nil
	}, nil
}

// relay is a terminal session served by a helper: client records go to the
// helper as frames, the helper's frames come back as records.
type relay struct {
	ch      *Channel
	conn    *os.File
	session *launcher.Session
	rec     *sessionRecorder
	log     func(string, ...any)

	ended      chan string
	readerDone chan struct{}
	// halted is closed by End; it releases an output tap waiting on a full
	// Strict recording queue.
	halted  chan struct{}
	stopped atomic.Bool
	endOnce sync.Once
}

// startRelay asks the launcher for the session and starts the reader. A
// refusal or an unreachable launcher ends the session with its reason; the
// ticket is spent by then.
func startRelay(l Launcher, ch *Channel, device, login string, st terminalStart, log func(string, ...any), rec *sessionRecorder) kindSession {
	ours, theirs, err := launcher.SocketPair()
	if err != nil {
		log("session: terminal: session channel: %v", err)
		return endedKind(CodeKindUnavailable)
	}
	req := launcher.Request{Kind: launcher.KindTerminal, Device: device, Login: login, Cols: st.Cols, Rows: st.Rows, Term: st.Term}
	sess, err := l.Start(context.Background(), req, theirs)
	_ = theirs.Close()
	if err != nil {
		_ = ours.Close()
		log("session: terminal for %q did not start: %v", login, err)
		return endedKind(refusalReason(err))
	}
	r := &relay{
		ch: ch, conn: ours, session: sess, rec: rec, log: log,
		ended:      make(chan string, 1),
		readerDone: make(chan struct{}),
		halted:     make(chan struct{}),
	}
	go r.read()
	return r
}

// refusalReason maps a launcher refusal to the session's close reason.
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

// read relays the helper's frames until its exit frame or the channel's end.
func (r *relay) read() {
	defer close(r.readerDone)
	fr := launcher.NewFrameReader(r.conn)
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			if !r.stopped.Load() {
				r.log("session: terminal: the helper's channel ended without an exit: %v", err)
				r.ended <- CloseHelperFailed
			}
			return
		}
		switch f.Type {
		case launcher.FrameData:
			r.rec.output(f.Data, r.halted)
			if r.stopped.Load() {
				return
			}
			if err := r.ch.WriteMessage(TypeData, f.Data); err != nil {
				// The session's end is decided by the server.
				return
			}
		case launcher.FrameExit:
			if r.stopped.Swap(true) {
				return
			}
			r.rec.exit(int(f.Code))
			if r.ch.WriteMessage(TypeExit, exitBody(int(f.Code))) == nil {
				r.ended <- CloseExited
			} else {
				r.ended <- ""
			}
			return
		default:
			r.log("session: terminal: unexpected frame %d from the helper", f.Type)
			if !r.stopped.Swap(true) {
				r.ended <- CloseHelperFailed
			}
			return
		}
	}
}

func (r *relay) Handle(m Message) error {
	in, err := decodeTerminalInput(m)
	if err != nil {
		return err
	}
	if in.resize != nil {
		err = launcher.WriteFrame(r.conn, launcher.Frame{Type: launcher.FrameResize, Cols: uint16(in.resize.Cols), Rows: uint16(in.resize.Rows)})
		if err == nil {
			r.rec.resize(uint16(in.resize.Cols), uint16(in.resize.Rows))
		}
	} else {
		for p := in.data; len(p) > 0 && err == nil; {
			n := min(len(p), launcher.MaxFrameData)
			err = launcher.WriteFrame(r.conn, launcher.Frame{Type: launcher.FrameData, Data: p[:n]})
			p = p[n:]
		}
	}
	if err != nil && r.stopped.Load() {
		// The helper exited or the session is ending; the end path reports it.
		return nil
	}
	return err
}

func (r *relay) Ended() <-chan string { return r.ended }

// End stops the output and closes the channel: the helper reads EOF and
// runs the session's end path (SIGHUP, SIGKILL after its delay, PAM close).
func (r *relay) End() {
	r.endOnce.Do(func() {
		r.stopped.Store(true)
		close(r.halted)
		_ = r.conn.Close()
	})
}

// Wait joins the reader and closes the request connection; the helper
// finishes the session on its own.
func (r *relay) Wait() {
	<-r.readerDone
	r.End()
	_ = r.session.Close()
}

// endedKind is a terminal that never started: it ends the session with
// reason and drops every record until then.
func endedKind(reason string) kindSession {
	k := &exitedKind{ended: make(chan string, 1)}
	k.ended <- reason
	return k
}

type exitedKind struct{ ended chan string }

func (exitedKind) Handle(Message) error    { return nil }
func (k *exitedKind) Ended() <-chan string { return k.ended }
func (exitedKind) End()                    {}
func (exitedKind) Wait()                   {}

//go:build cgo && (linux || darwin)

package sessionhelper

import (
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/localport/agent/internal/launcher"
)

// startPipe runs `sh -c command` on pipes as the test's user and returns the
// session and the agent's frame reader.
func startPipe(t *testing.T, command string) (*pipeSession, *launcher.FrameReader) {
	t.Helper()
	agent, helper, err := launcher.SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	plan := spawnPlan{path: "/bin/sh", args: []string{"sh", "-c", command}, env: []string{"PATH=/usr/bin:/bin"}, dir: "/"}
	p, err := startPipeSession(&frameWriter{w: helper}, plan, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p.finish()
		p.Wait()
		agent.Close()
		helper.Close()
	})
	_ = agent.SetDeadline(time.Now().Add(15 * time.Second))
	return p, launcher.NewFrameReader(agent)
}

// The file server's event pipe is descriptor 3: a valid event is relayed as
// an event frame; an invalid one ends the session without its exit frame.
func TestPipeSessionRelaysOnlyValidEvents(t *testing.T) {
	agent, helper, err := launcher.SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	defer helper.Close()
	// Frames: type 6, uint32 BE length, JSON (38 bytes valid, 14 invalid).
	script := `printf '\006\000\000\000\046{"op":"list","path":"/","result":"ok"}' >&3; sleep 0.2; ` +
		`printf '\006\000\000\000\016{"op":"chmod"}' >&3; sleep 30`
	plan := spawnPlan{path: "/bin/sh", args: []string{"sh", "-c", script}, env: []string{"PATH=/usr/bin:/bin"}, dir: "/", events: true}
	p, err := startPipeSession(&frameWriter{w: helper}, plan, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { p.finish(); p.Wait() }()
	_ = agent.SetDeadline(time.Now().Add(15 * time.Second))
	fr := launcher.NewFrameReader(agent)
	f, err := fr.ReadFrame()
	if err != nil || f.Type != launcher.FrameEvent || string(f.Data) != `{"op":"list","path":"/","result":"ok"}` {
		t.Fatalf("first frame %+v %q, %v", f, f.Data, err)
	}
	select {
	case <-p.endedC():
	case <-time.After(10 * time.Second):
		t.Fatal("an invalid event did not end the session")
	}
}

// readToExit collects stdout and stderr frames up to the exit frame.
func readToExit(t *testing.T, fr *launcher.FrameReader) (stdout, stderr string, code int32) {
	t.Helper()
	var out, errOut strings.Builder
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("no exit frame: %v; stdout %q stderr %q", err, out.String(), errOut.String())
		}
		switch f.Type {
		case launcher.FrameData:
			out.Write(f.Data)
		case launcher.FrameStderr:
			errOut.Write(f.Data)
		case launcher.FrameExit:
			return out.String(), errOut.String(), f.Code
		}
	}
}

// stdout and stderr travel in their own frames; the exit status follows all output.
func TestPipeSessionSeparatesStderrAndExit(t *testing.T) {
	_, fr := startPipe(t, "echo out; echo err >&2; exit 4")
	stdout, stderr, code := readToExit(t, fr)
	if stdout != "out\n" || stderr != "err\n" || code != 4 {
		t.Fatalf("stdout %q stderr %q exit %d", stdout, stderr, code)
	}
}

// stdin data reaches the command and the eof frame closes its stdin.
func TestPipeSessionStdinAndEOF(t *testing.T) {
	p, fr := startPipe(t, "cat")
	if err := p.handle(launcher.Frame{Type: launcher.FrameData, Data: []byte("piped")}); err != nil {
		t.Fatal(err)
	}
	if err := p.handle(launcher.Frame{Type: launcher.FrameEOF}); err != nil {
		t.Fatal(err)
	}
	stdout, _, code := readToExit(t, fr)
	if stdout != "piped" || code != 0 {
		t.Fatalf("stdout %q exit %d", stdout, code)
	}
	if err := p.handle(launcher.Frame{Type: launcher.FrameResize, Cols: 80, Rows: 24}); err == nil {
		t.Fatal("a resize without a PTY was accepted")
	}
}

// gateWriter is the helper's side of the channel with one parked write: the
// first frame of type park blocks inside Write, as a write to an agent that
// stopped reading does, until release.
type gateWriter struct {
	w           io.Writer
	park        byte
	parked      sync.Once
	entered     chan struct{}
	released    sync.Once
	releaseChan chan struct{}
}

func newGate(w io.Writer, park byte) *gateWriter {
	return &gateWriter{w: w, park: park, entered: make(chan struct{}), releaseChan: make(chan struct{})}
}

func (g *gateWriter) Write(b []byte) (int, error) {
	if len(b) > 0 && b[0] == g.park {
		first := false
		g.parked.Do(func() { first = true })
		if first {
			close(g.entered)
			<-g.releaseChan
		}
	}
	return g.w.Write(b)
}

func (g *gateWriter) release() { g.released.Do(func() { close(g.releaseChan) }) }

// waitParked fails the test when no frame reaches the gate within 10 s.
func (g *gateWriter) waitParked(t *testing.T) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("no frame reached the gate")
	}
}

// waitUntil polls cond, which reads session state under its own lock.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitClosed fails the test, naming what, when c does not close within 10 s.
func waitClosed(t *testing.T, what string, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting until %s", what)
	}
}

// startPipeAgent is startPipe returning the agent's end of the channel too;
// gate, when it parks a frame type, sits between the session and the channel.
func startPipeAgent(t *testing.T, command string, park byte) (*pipeSession, *os.File, *gateWriter) {
	t.Helper()
	agent, helper, err := launcher.SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	gate := newGate(helper, park)
	plan := spawnPlan{path: "/bin/sh", args: []string{"sh", "-c", command}, env: []string{"PATH=/usr/bin:/bin"}, dir: "/"}
	p, err := startPipeSession(&frameWriter{w: gate}, plan, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		gate.release()
		p.finish()
		p.Wait()
		agent.Close()
		helper.Close()
	})
	_ = agent.SetDeadline(time.Now().Add(15 * time.Second))
	return p, agent, gate
}

// expectFrames reads the frames the session wrote, in order, then requires
// that nothing follows.
func expectFrames(t *testing.T, agent *os.File, want ...launcher.Frame) {
	t.Helper()
	fr := launcher.NewFrameReader(agent)
	for i, w := range want {
		f, err := fr.ReadFrame()
		if err != nil || f.Type != w.Type || (w.Data != nil && string(f.Data) != string(w.Data)) {
			t.Fatalf("frame %d: %+v %q, %v; want type %d %q", i, f, f.Data, err, w.Type, w.Data)
		}
	}
	expectNoFrame(t, agent)
}

// expectNoFrame requires that nothing follows on the channel once the session
// ended: the read times out.
func expectNoFrame(t *testing.T, agent *os.File) {
	t.Helper()
	_ = agent.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if f, err := launcher.NewFrameReader(agent).ReadFrame(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("frame %+v, %v after the session's last frame; want none", f, err)
	}
}

func (p *pipeSession) sawExit() bool {
	p.procMu.Lock()
	defer p.procMu.Unlock()
	return p.exitSeen
}

var endRevoked = launcher.Frame{Type: launcher.FrameEnd, Data: []byte(launcher.EndFullDiskAccessRevoked)}

// ending is endSession running for a started session, as Run runs it.
type ending struct {
	revoked  chan string
	released chan struct{}
	done     chan struct{}
}

// startEnding runs endSession for k in the background; the agent never closes
// the channel, and release records that it ran.
func startEnding(t *testing.T, k helperSession, out *frameWriter) *ending {
	e := &ending{revoked: make(chan string, 1), released: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(e.done)
		endSession(k, out, make(chan struct{}), e.revoked, func() { close(e.released) }, func(string) {}, t.Logf)
	}()
	return e
}

// pollablePair is a socket pair whose ends both take deadlines, as the
// helper's channel does.
func pollablePair(t *testing.T) (agent, helper *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		unix.CloseOnExec(fd)
		if err := unix.SetNonblock(fd, true); err != nil {
			t.Fatal(err)
		}
	}
	return os.NewFile(uintptr(fds[0]), "agent"), os.NewFile(uintptr(fds[1]), "helper")
}

// blockedWriter is the helper's end of a pollable pair that reports a write
// blocked on a full socket: before any deadline is set, a write the agent
// never reads does not return.
type blockedWriter struct {
	f     *os.File
	since atomic.Int64 // start of the write in progress, unix nanoseconds; 0 when none
}

func (w *blockedWriter) Write(b []byte) (int, error) {
	w.since.Store(time.Now().UnixNano())
	defer w.since.Store(0)
	return w.f.Write(b)
}

func (w *blockedWriter) SetWriteDeadline(t time.Time) error { return w.f.SetWriteDeadline(t) }

// waitBlocked waits until a write has been in progress for 100 ms.
func (w *blockedWriter) waitBlocked(t *testing.T) {
	t.Helper()
	waitUntil(t, "an output write blocked on the agent", func() bool {
		s := w.since.Load()
		return s != 0 && time.Since(time.Unix(0, s)) > 100*time.Millisecond
	})
}

// setDrainBound shortens sessionDrainBound for one test.
func setDrainBound(t *testing.T, d time.Duration) {
	old := sessionDrainBound
	sessionDrainBound = d
	t.Cleanup(func() { sessionDrainBound = old })
}

// A revocation while an output write is parked on an agent that stopped
// reading hangs up the command and releases the login before the output
// moves; the end frame follows that output once the agent reads again.
func TestPipeSessionEndWhileOutputIsParked(t *testing.T) {
	p, agent, gate := startPipeAgent(t, "echo x; sleep 30", launcher.FrameData)
	gate.waitParked(t)
	e := startEnding(t, p, p.out)
	e.revoked <- launcher.EndFullDiskAccessRevoked
	waitClosed(t, "the login was released with the output parked", e.released)
	gate.release()
	waitClosed(t, "endSession returned", e.done)
	expectFrames(t, agent, launcher.Frame{Type: launcher.FrameData, Data: []byte("x\n")}, endRevoked)
}

// A command that ends while the end frame is parked writes no exit frame: the
// end frame stays the session's last.
func TestPipeSessionExitWhileEndIsParked(t *testing.T) {
	p, agent, gate := startPipeAgent(t, "cat", launcher.FrameEnd)
	e := startEnding(t, p, p.out)
	e.revoked <- launcher.EndFullDiskAccessRevoked
	gate.waitParked(t)
	waitUntil(t, "the command exited and the output stopped", func() bool { return p.sawExit() && p.stopped.Load() })
	gate.release()
	waitClosed(t, "endSession returned", e.done)
	p.Wait()
	expectFrames(t, agent, endRevoked)
}

// An end after the exit frame writes nothing: the exit frame stays last.
func TestPipeSessionEndAfterExitIsIgnored(t *testing.T) {
	p, agent, _ := startPipeAgent(t, "exit 3", 0)
	if _, _, code := readToExit(t, launcher.NewFrameReader(agent)); code != 3 {
		t.Fatalf("exit %d", code)
	}
	p.Wait()
	e := startEnding(t, p, p.out)
	e.revoked <- launcher.EndFullDiskAccessRevoked
	waitClosed(t, "endSession returned", e.done)
	expectNoFrame(t, agent)
}

// A command that exits by itself while its output is parked releases the
// login at once, and still delivers its output and exit frame afterwards.
func TestEndSessionReleasesThenDeliversTheExitFrame(t *testing.T) {
	p, agent, gate := startPipeAgent(t, "read x; echo hi; exit 3", launcher.FrameData)
	e := startEnding(t, p, p.out)
	if err := p.handle(launcher.Frame{Type: launcher.FrameData, Data: []byte("go\n")}); err != nil {
		t.Fatal(err)
	}
	gate.waitParked(t)
	waitClosed(t, "the login was released with the output parked", e.released)
	gate.release()
	waitClosed(t, "endSession returned", e.done)
	expectFrames(t, agent, launcher.Frame{Type: launcher.FrameData, Data: []byte("hi\n")}, launcher.Frame{Type: launcher.FrameExit})
}

// An agent that never reads cannot hold the session: the parked output write
// fails at sessionDrainBound, the readers return and endSession returns.
func TestEndSessionBoundsAStalledAgent(t *testing.T) {
	setDrainBound(t, 200*time.Millisecond)
	agent, helper := pollablePair(t)
	defer agent.Close()
	defer helper.Close()
	w := &blockedWriter{f: helper}
	plan := spawnPlan{path: "/bin/sh", args: []string{"sh", "-c", "yes"}, env: []string{"PATH=/usr/bin:/bin"}, dir: "/"}
	p, err := startPipeSession(&frameWriter{w: w}, plan, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	// Closing the helper's end first fails a write still pending.
	defer func() { helper.Close(); p.finish(); p.Wait() }()
	w.waitBlocked(t)
	e := startEnding(t, p, p.out)
	e.revoked <- launcher.EndFullDiskAccessRevoked
	waitClosed(t, "the login was released", e.released)
	waitClosed(t, "endSession returned", e.done)
	waitClosed(t, "the output readers returned", p.readersDone)
}

// The end path ends a command that ignores SIGHUP with SIGKILL to its group,
// so no frame follows and Wait returns.
func TestPipeSessionEndKillsTheCommand(t *testing.T) {
	p, _ := startPipe(t, "trap '' HUP; while :; do sleep 1; done")
	time.Sleep(100 * time.Millisecond)
	pid := p.cmd.Process.Pid
	p.finish()
	done := make(chan struct{})
	go func() { p.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(terminalKillDelay + 5*time.Second):
		t.Fatal("Wait did not return after the SIGKILL")
	}
	if proc, err := os.FindProcess(pid); err == nil && proc.Signal(nil) == nil {
		// Reaped by the waiter: a signal to the pid fails.
		t.Fatalf("command %d still runs", pid)
	}
}

//go:build cgo && (linux || darwin)

package sessionhelper

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/localport/agent/internal/launcher"
)

// pipeSession is an exec session without a PTY: the command's stdin, stdout
// and stderr are pipes. Two reader goroutines copy stdout to data frames and
// stderr to stderr frames; a waiter observes the exit, drains the remaining
// output for at most terminalDrainTimeout and sends the exit frame. The
// command runs in its own process group (Setsid), which the end path signals
// while the command is unreaped.
type pipeSession struct {
	out    *frameWriter
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser
	// events is the read end of the file server's event pipe, nil otherwise.
	events *os.File

	ended     chan struct{}
	endedOnce sync.Once
	// readersDone is closed once both output readers returned.
	readersDone chan struct{}
	waiterDone  chan struct{}
	stopped     atomic.Bool
	// outMu orders every output frame before the exit frame.
	outMu sync.Mutex

	endOnce sync.Once
	// procMu orders the end path's signals against the reap; exitSeen is set
	// once the exit is observed, after which the group is never signalled.
	procMu   sync.Mutex
	exitSeen bool
	kill     *time.Timer
	killDone chan struct{}
	exitCode int

	observeExit func(pid int) error
	log         func(format string, args ...any)
}

// startPipeSession starts plan with pipes. On error nothing was started.
func startPipeSession(out *frameWriter, plan spawnPlan, log func(string, ...any)) (*pipeSession, error) {
	cmd := &exec.Cmd{
		Path:        plan.path,
		Args:        plan.args,
		Env:         plan.env,
		Dir:         plan.dir,
		SysProcAttr: &syscall.SysProcAttr{Setsid: true, Credential: plan.cred},
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	var events *os.File
	if plan.events {
		r, w, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		events, cmd.ExtraFiles = r, []*os.File{w}
		defer w.Close() // the child holds its copy once started
	}
	if err := startChild(cmd); err != nil {
		if events != nil {
			_ = events.Close()
		}
		return nil, err
	}
	p := &pipeSession{
		out: out, cmd: cmd, stdin: stdin, stdout: stdout, stderr: stderr,
		ended:       make(chan struct{}),
		readersDone: make(chan struct{}),
		waiterDone:  make(chan struct{}),
		killDone:    make(chan struct{}),
		observeExit: observeExit,
		log:         log,
	}
	var readers sync.WaitGroup
	readers.Go(func() { p.readOutput(stdout, launcher.FrameData) })
	readers.Go(func() { p.readOutput(stderr, launcher.FrameStderr) })
	if events != nil {
		p.events = events
		readers.Go(func() { p.readEvents(events) })
	}
	go func() { readers.Wait(); close(p.readersDone) }()
	go p.wait()
	return p, nil
}

func (p *pipeSession) endedC() <-chan struct{} { return p.ended }

func (p *pipeSession) markEnded() { p.endedOnce.Do(func() { close(p.ended) }) }

// handle applies one frame from the agent: stdin bytes, or the end of stdin.
// A resize has no PTY to apply to and is an error.
func (p *pipeSession) handle(f launcher.Frame) error {
	var err error
	switch f.Type {
	case launcher.FrameData:
		_, err = p.stdin.Write(f.Data)
	case launcher.FrameEOF:
		err = p.stdin.Close()
	default:
		return errors.New("sessionhelper: unexpected frame from the agent")
	}
	if err != nil && p.stopped.Load() {
		return nil
	}
	if errors.Is(err, syscall.EPIPE) || errors.Is(err, io.ErrClosedPipe) {
		// The command closed its stdin; its exit ends the session.
		return nil
	}
	return err
}

// readOutput copies r to frames of typ until r ends or the output stops.
func (p *pipeSession) readOutput(r io.Reader, typ byte) {
	buf := make([]byte, maxTerminalOutput)
	for {
		n, err := r.Read(buf)
		if n > 0 && !p.writeOutput(typ, buf[:n]) {
			return
		}
		if err != nil {
			return
		}
	}
}

// readEvents relays the child's event frames: each must be a valid file
// event, else the session ends. The event pipe is the file server's own
// account's, so nothing it sends is trusted unchecked.
func (p *pipeSession) readEvents(r io.Reader) {
	fr := launcher.NewFrameReader(r)
	for {
		f, err := fr.ReadFrame()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil || f.Type != launcher.FrameEvent {
			p.log("sessionhelper: bad event pipe frame: %v", err)
			p.finish()
			return
		}
		if _, err := launcher.ParseFileEvent(f.Data); err != nil {
			p.log("sessionhelper: bad file event: %v", err)
			p.finish()
			return
		}
		if !p.writeOutput(launcher.FrameEvent, f.Data) {
			return
		}
	}
}

func (p *pipeSession) writeOutput(typ byte, b []byte) bool {
	p.outMu.Lock()
	defer p.outMu.Unlock()
	if p.stopped.Load() {
		return false
	}
	return p.out.write(launcher.Frame{Type: typ, Data: b}) == nil
}

// wait observes the command's exit, drains its output, sends the exit frame
// when the session did not end first, and reaps it.
func (p *pipeSession) wait() {
	defer close(p.waiterDone)
	pid := p.cmd.Process.Pid
	if err := p.observeExit(pid); err != nil {
		p.log("sessionhelper: observe the exit of %d: %v", pid, err)
	}
	p.procMu.Lock()
	p.exitSeen = true
	if p.kill != nil && p.kill.Stop() {
		close(p.killDone)
	}
	p.procMu.Unlock()
	drain := time.NewTimer(terminalDrainTimeout)
	select {
	case <-p.readersDone:
	case <-drain.C:
	}
	drain.Stop()
	// Unblocks readers held by a child that kept the pipes open.
	_ = p.stdout.Close()
	_ = p.stderr.Close()
	if p.events != nil {
		_ = p.events.Close()
	}
	<-p.readersDone
	_ = p.cmd.Wait()
	p.exitCode = exitCode(p.cmd.ProcessState)
	p.outMu.Lock()
	if !p.stopped.Swap(true) {
		_ = p.out.write(launcher.Frame{Type: launcher.FrameExit, Code: int32(p.exitCode)})
	}
	p.outMu.Unlock()
	p.markEnded()
	p.finish()
}

// finish is the end path, run once for every end: it stops the output,
// closes stdin, and while the command is unreaped sends its group SIGHUP and
// arms SIGKILL at terminalKillDelay.
func (p *pipeSession) finish() {
	p.endOnce.Do(func() {
		p.stopped.Store(true)
		p.markEnded()
		_ = p.stdin.Close()
		p.procMu.Lock()
		defer p.procMu.Unlock()
		if p.exitSeen {
			close(p.killDone)
			return
		}
		_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGHUP)
		p.kill = time.AfterFunc(terminalKillDelay, func() {
			p.procMu.Lock()
			defer p.procMu.Unlock()
			if !p.exitSeen {
				_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
			}
			close(p.killDone)
		})
	})
}

// Wait joins the SIGKILL step and the waiter; a command still unreaped
// terminalReapTimeout after the SIGKILL is logged and left to the waiter.
func (p *pipeSession) Wait() {
	<-p.killDone
	reap := time.NewTimer(terminalReapTimeout)
	defer reap.Stop()
	select {
	case <-p.waiterDone:
	case <-reap.C:
		p.log("sessionhelper: command %d not reaped %v after SIGKILL", p.cmd.Process.Pid, terminalReapTimeout)
	}
}

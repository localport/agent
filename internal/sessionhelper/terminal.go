//go:build cgo && (linux || darwin)

package sessionhelper

import (
	"errors"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"

	"github.com/localport/agent/internal/launcher"
)

const (
	// terminalDrainTimeout and maxTerminalDrain bound the output read after
	// the shell exited by itself, before the exit frame.
	terminalDrainTimeout = time.Second
	maxTerminalDrain     = 64 << 10
	// terminalKillDelay is the time from the end decision to the SIGKILL of
	// the shell's group and the recorded session leader.
	terminalKillDelay = 5 * time.Second
	// terminalReapTimeout bounds Wait's join of the reap after the SIGKILL.
	terminalReapTimeout = time.Second
	// maxTerminalOutput bounds the PTY output one data frame carries.
	maxTerminalOutput = 16 << 10
)

// spawnPlan is how a terminal session starts the login's shell: argv0 is
// "-<basename>", env is complete (TERM included), dir is the working
// directory and cred the identity the child takes before exec.
type spawnPlan struct {
	path string
	args []string
	env  []string
	dir  string
	cred *syscall.Credential
	// events gives a pipe session descriptor 3, an event pipe whose
	// FrameEvent frames the helper validates and relays (the file server).
	events bool
}

// frameWriter serializes the frames the helper writes to the channel.
type frameWriter struct {
	mu sync.Mutex
	w  *os.File
}

func (fw *frameWriter) write(f launcher.Frame) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	return launcher.WriteFrame(fw.w, f)
}

// terminal is one terminal session: the shell in a PTY, a reader goroutine
// copying the master's output to data frames, and a waiter goroutine that
// observes the shell's exit and, when it exited by itself, sends the exit
// frame. The helper is the shell's parent and holds it unreaped until the
// end path ran (A6), so no signal names a reused pid.
type terminal struct {
	out    *frameWriter
	master *os.File
	slave  *os.File
	cmd    *exec.Cmd

	// ended is closed once the exit frame was sent or the output stopped.
	ended      chan struct{}
	endedOnce  sync.Once
	exited     chan struct{} // closed once the shell is reaped
	readerDone chan struct{}
	waiterDone chan struct{}

	// stopped ends the output: set by the end path and by the exit frame.
	stopped atomic.Bool
	// outMu orders every data frame before the exit frame.
	outMu sync.Mutex
	// drained counts the bytes read after the exit; drainFull is closed when
	// it reaches maxTerminalDrain.
	drained   atomic.Int64
	drainFull chan struct{}
	drainOnce sync.Once

	endOnce sync.Once
	// procMu orders the end path's signals against the exit. exitSeen is set
	// once the waiter observed the exit, before the reap; exitUnobserved is
	// set before the reap when it cannot observe it. Under either, no signal
	// names the shell's group, whose number may be reused.
	procMu         sync.Mutex
	exitSeen       bool
	exitUnobserved bool
	// leader is the slave's session leader recorded at the end decision, nil
	// when there is none, it is the shell, or it was released.
	leader *sessionLeader
	kill   *time.Timer
	// killDone is closed once the SIGKILL step ran or became unnecessary.
	killDone chan struct{}

	// exitCode is the shell's exit status once reaped.
	exitCode int

	// observeExit blocks until the shell exited, without reaping it.
	observeExit func(pid int) error
	log         func(format string, args ...any)
}

// sessionLeader is a process held for the end path's SIGKILL: by pidfd on
// Linux, by pid (pidfd -1) on macOS and on Linux without pidfd_open.
type sessionLeader struct {
	pid   int
	pidfd int
}

// observeExit is the terminal's exit observer; tests replace it before the
// session starts.
var observeExit = waitExited

// openPTY opens a PTY pair of the given size.
func openPTY(cols, rows uint16) (master, slave *os.File, err error) {
	master, slave, err = pty.Open()
	if err != nil {
		return nil, nil, err
	}
	if err := pty.Setsize(master, &pty.Winsize{Cols: cols, Rows: rows}); err != nil {
		_ = master.Close()
		_ = slave.Close()
		return nil, nil, err
	}
	return master, slave, nil
}

// startTerminal starts plan on slave. On error nothing was started and the
// caller still owns master and slave.
func startTerminal(out *frameWriter, master, slave *os.File, plan spawnPlan, log func(string, ...any)) (*terminal, error) {
	cmd := &exec.Cmd{
		Path:   plan.path,
		Args:   plan.args,
		Env:    plan.env,
		Dir:    plan.dir,
		Stdin:  slave,
		Stdout: slave,
		Stderr: slave,
		// Ctty is the child's fd 0, the slave.
		SysProcAttr: &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0, Credential: plan.cred},
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	k := &terminal{
		out: out, master: master, slave: slave, cmd: cmd,
		ended:      make(chan struct{}),
		exited:     make(chan struct{}),
		readerDone: make(chan struct{}),
		waiterDone: make(chan struct{}),
		drainFull:  make(chan struct{}),
		killDone:   make(chan struct{}),

		observeExit: observeExit,
		log:         log,
	}
	go k.readOutput()
	go k.wait()
	return k, nil
}

// handle applies one frame from the agent: input for the PTY or a new size.
func (k *terminal) handle(f launcher.Frame) error {
	var err error
	switch f.Type {
	case launcher.FrameData:
		_, err = k.master.Write(f.Data)
	case launcher.FrameResize:
		err = pty.Setsize(k.master, &pty.Winsize{Cols: f.Cols, Rows: f.Rows})
	case launcher.FrameEOF:
		// A PTY has no end of input; the line discipline sees ^D if the
		// client sends one.
		return nil
	default:
		return errors.New("sessionhelper: unexpected frame from the agent")
	}
	if err != nil && k.over() {
		// The shell exited or the session is ending; the end path reports it.
		return nil
	}
	return err
}

func (k *terminal) markEnded() { k.endedOnce.Do(func() { close(k.ended) }) }

func (k *terminal) endedC() <-chan struct{} { return k.ended }

// Wait joins the reader, the SIGKILL step and the waiter. A shell still
// unreaped terminalReapTimeout after the SIGKILL (uninterruptible sleep) is
// logged and left to the waiter.
func (k *terminal) Wait() {
	<-k.readerDone
	<-k.killDone
	reap := time.NewTimer(terminalReapTimeout)
	defer reap.Stop()
	select {
	case <-k.waiterDone:
	case <-reap.C:
		k.log("sessionhelper: shell %d not reaped %v after SIGKILL", k.cmd.Process.Pid, terminalReapTimeout)
	}
}

// over reports whether the shell was reaped or the output stopped.
func (k *terminal) over() bool {
	select {
	case <-k.exited:
		return true
	default:
		return k.stopped.Load()
	}
}

// readOutput copies the master's output to data frames until the master
// fails, closes, or the output stops.
func (k *terminal) readOutput() {
	defer close(k.readerDone)
	buf := make([]byte, maxTerminalOutput)
	for {
		n, err := k.master.Read(buf)
		if n > 0 && !k.writeOutput(buf[:n]) {
			return
		}
		if err != nil {
			return
		}
	}
}

// writeOutput sends p as one data frame unless the output stopped. A failed
// write ends the output only; the end comes from the channel's EOF.
func (k *terminal) writeOutput(p []byte) bool {
	k.outMu.Lock()
	defer k.outMu.Unlock()
	if k.stopped.Load() {
		return false
	}
	if err := k.out.write(launcher.Frame{Type: launcher.FrameData, Data: p}); err != nil {
		return false
	}
	select {
	case <-k.exited:
		if k.drained.Add(int64(len(p))) >= maxTerminalDrain {
			k.drainOnce.Do(func() { close(k.drainFull) })
		}
	default:
	}
	return true
}

// wait reaps the shell. When it exited by itself, it drains the remaining
// output and sends the exit frame.
func (k *terminal) wait() {
	defer close(k.waiterDone)
	pid := k.cmd.Process.Pid
	if err := k.observeExit(pid); err != nil {
		k.log("sessionhelper: observe the exit of %d: %v", pid, err)
		k.procMu.Lock()
		k.exitUnobserved = true
		k.procMu.Unlock()
	} else {
		k.setExitSeen()
	}
	_ = k.cmd.Wait()
	k.procMu.Lock()
	k.exitSeen = true
	if k.kill != nil && !k.leaderAlive() && k.kill.Stop() {
		k.endKill()
	}
	k.procMu.Unlock()
	_ = k.slave.Close()
	k.exitCode = exitCode(k.cmd.ProcessState)
	close(k.exited)
	if k.stopped.Load() {
		k.markEnded()
		return
	}
	drain := time.NewTimer(terminalDrainTimeout)
	select {
	case <-k.readerDone:
	case <-k.drainFull:
	case <-drain.C:
	}
	drain.Stop()

	k.outMu.Lock()
	if !k.stopped.Swap(true) {
		_ = k.out.write(launcher.Frame{Type: launcher.FrameExit, Code: int32(k.exitCode)})
	}
	k.outMu.Unlock()
	k.markEnded()
	k.finish()
}

func (k *terminal) setExitSeen() {
	k.procMu.Lock()
	k.exitSeen = true
	k.procMu.Unlock()
}

// finish is the end path, run once for every end: it stops the output,
// records the slave's session leader, sends SIGHUP to the shell, hangs up
// the foreground group and the session leader where the kernel does not
// (macOS), arms the SIGKILL step at terminalKillDelay while either may be
// alive, revokes the slave (macOS) and closes the master, which hangs up the
// slave's session.
func (k *terminal) finish() {
	k.endOnce.Do(func() {
		k.stopped.Store(true)
		k.markEnded()
		k.procMu.Lock()
		foreground := k.foregroundGroup()
		k.leader = k.recordLeader(foreground)
		if !k.exitSeen {
			_ = k.cmd.Process.Signal(syscall.SIGHUP)
		}
		// The shell's group number may be reused once its exit is seen.
		if foreground != k.cmd.Process.Pid || k.groupSignallable() {
			hangupSession(foreground, k.leader)
		}
		if !k.exitSeen || k.leaderAlive() {
			k.kill = time.AfterFunc(terminalKillDelay, k.killSession)
		} else {
			k.endKill()
		}
		k.procMu.Unlock()
		// Before the master's close, which frees the slave's name for reuse.
		if err := revokeSlave(k.slave.Name()); err != nil {
			k.log("sessionhelper: revoke %s: %v", k.slave.Name(), err)
		}
		_ = k.master.Close()
	})
}

// foregroundGroup returns the slave's foreground process group, read through
// the master, or 0 when it has none.
func (k *terminal) foregroundGroup() int {
	rc, err := k.master.SyscallConn()
	if err != nil {
		return 0
	}
	pgrp, ioctlErr := 0, error(nil)
	if err := rc.Control(func(fd uintptr) { pgrp, ioctlErr = unix.IoctlGetInt(int(fd), unix.TIOCGPGRP) }); err != nil || ioctlErr != nil || pgrp <= 0 {
		return 0
	}
	return pgrp
}

// recordLeader returns the session leader of the foreground process group.
// It returns nil when there is no foreground group or no session leader, or
// when the leader is the shell, which the group SIGKILL covers.
func (k *terminal) recordLeader(pgrp int) *sessionLeader {
	if pgrp <= 0 {
		return nil
	}
	sid, err := unix.Getsid(pgrp)
	if err != nil || sid == k.cmd.Process.Pid {
		return nil
	}
	l, err := holdLeader(sid)
	if err != nil {
		if !errors.Is(err, unix.ESRCH) {
			k.log("sessionhelper: hold the session leader %d: %v", sid, err)
		}
		return nil
	}
	return l
}

// leaderAlive reports whether the recorded session leader still exists.
// procMu held.
func (k *terminal) leaderAlive() bool {
	return k.leader != nil && k.leader.signal(0) == nil
}

// killSession is the SIGKILL step: the shell's group, which Setsid made its
// own, unless its exit was observed, and the recorded session leader. Other
// foreground groups are left alone.
func (k *terminal) killSession() {
	k.procMu.Lock()
	defer k.procMu.Unlock()
	switch {
	case k.groupSignallable():
		_ = syscall.Kill(-k.cmd.Process.Pid, syscall.SIGKILL)
	case !k.exitSeen:
		// os.Process signals through a pidfd on Linux; elsewhere it refuses
		// a process it has reaped.
		_ = k.cmd.Process.Signal(syscall.SIGKILL)
	}
	if k.leader != nil {
		_ = k.leader.signal(unix.SIGKILL)
	}
	k.endKill()
}

// groupSignallable reports whether the shell's group may be signalled by
// number: its exit was neither observed nor unobservable. procMu held.
func (k *terminal) groupSignallable() bool { return !k.exitSeen && !k.exitUnobserved }

// endKill releases the recorded leader and closes killDone. procMu held; it
// runs once, from finish, from the waiter after a successful Stop of the
// timer, or from the timer itself.
func (k *terminal) endKill() {
	if k.leader != nil {
		k.leader.release()
		k.leader = nil
	}
	close(k.killDone)
}

// exitCode is the process's exit status, or 128 + the signal that ended it.
func exitCode(ps *os.ProcessState) int {
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ps.ExitCode()
}

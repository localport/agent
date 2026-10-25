//go:build linux || darwin

package session

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/security"
)

const (
	// terminalDrainTimeout and maxTerminalDrain bound the output read after
	// the spawned process exited by itself, before the exit record.
	terminalDrainTimeout = time.Second
	maxTerminalDrain     = 64 << 10
	// terminalKillDelay is the time from the end decision to the SIGKILL of
	// the spawned process's group and the recorded session leader.
	terminalKillDelay = 5 * time.Second
	// terminalReapTimeout bounds Wait's join of the reap after the SIGKILL.
	terminalReapTimeout = time.Second
	// terminalStartFailedCode is the exit code sent when the process did not
	// start.
	terminalStartFailedCode = 127
	shellPath               = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

// terminalHost is where the terminal kind finds the host's login(1) and the
// SELinux mode. Tests replace its fields.
type terminalHost struct {
	// logins lists the candidate login(1) paths in order.
	logins []string
	// selinuxEnforce reads "1" when SELinux is enforcing.
	selinuxEnforce string
	// checkLogin refuses a resolved login(1) that is not root-owned and
	// root-writable only.
	checkLogin func(path string) error
}

var systemTerminalHost = &terminalHost{
	logins:         []string{"/bin/login", "/usr/bin/login"},
	selinuxEnforce: "/sys/fs/selinux/enforce",
	checkLogin:     security.CheckServiceBinary,
}

// kindFor returns the session kind that serves kind, or nil when this build
// has none. Unix builds serve terminal.
func kindFor(kind string) prepareKind {
	if kind == "terminal" {
		return systemTerminalHost.prepare
	}
	return nil
}

// spawnPlan is how a terminal session starts its process. env holds every
// variable except TERM, which the start record sets; it is empty for login(1),
// which builds its own. home, when it is a directory, is the working
// directory; otherwise it is /.
type spawnPlan struct {
	path string
	args []string
	env  []string
	home string
}

// prepare selects the terminal's spawn path at check time: login -f as root,
// the login's own shell otherwise.
func (h *terminalHost) prepare(login string, user *userRecord, root bool, log func(string, ...any)) (newKind, error) {
	if user == nil {
		return nil, fail(CodeKindUnavailable, "terminal: the ticket resolved no account")
	}
	var plan spawnPlan
	if root {
		p, err := h.loginPlan(login)
		if err != nil {
			return nil, err
		}
		plan = p
	} else {
		p, err := directPlan(user)
		if err != nil {
			return nil, err
		}
		plan = p
	}
	return func(ch *Channel, start []byte, _ string, _ *userRecord, rec *sessionRecorder) (kindSession, error) {
		st, err := parseTerminalStart(start)
		if err != nil {
			return nil, err
		}
		rec.start(time.Now(), uint16(st.Cols), uint16(st.Rows))
		return startTerminal(ch, plan, st, log, rec), nil
	}, nil
}

// loginPlan runs login -f <login> through the host's login(1), so the host's
// PAM account and session stacks apply. A host where login(1) cannot start
// the shell is refused: a root session never starts a shell around PAM.
func (h *terminalHost) loginPlan(login string) (spawnPlan, error) {
	path, err := h.selectLogin()
	if err != nil {
		return spawnPlan{}, &Error{Code: CodeKindUnavailable, Detail: "terminal: login(1)", Err: err}
	}
	// No -h: util-linux switches PAM to the remote service with it. Options
	// come before the operand for BSD and musl getopt; busybox dispatches on
	// argv0.
	return spawnPlan{path: path, args: []string{"login", "-f", login}}, nil
}

// selectLogin returns the resolved login(1) path. It refuses when SELinux is
// enforcing, since login(1) started from the agent's service domain is denied
// the transition to the login's domain, when no candidate path holds a
// login(1), and when the resolved one fails the ownership check.
func (h *terminalHost) selectLogin() (string, error) {
	mode, err := os.ReadFile(h.selinuxEnforce)
	switch {
	case err == nil && strings.TrimSpace(string(mode)) == "1":
		return "", errSELinuxEnforcing
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return "", fmt.Errorf("read the SELinux mode: %w", err)
	}
	for _, candidate := range h.logins {
		resolved, err := filepath.EvalSymlinks(candidate)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("resolve %s: %w", candidate, err)
		}
		if err := h.checkLogin(resolved); err != nil {
			return "", fmt.Errorf("%s: %w", candidate, err)
		}
		return resolved, nil
	}
	return "", fmt.Errorf("%s: %w", strings.Join(h.logins, " or "), errNoLogin)
}

// The reasons a root terminal is refused before the ticket is spent.
var (
	errSELinuxEnforcing = errcode.New(errcode.SELinuxEnforcing)
	errNoLogin          = errcode.New(errcode.NoLogin)
)

// directPlan runs the login shell of the agent's own user, as a login shell
// (argv0 -<basename>) with an environment built from scratch.
func directPlan(user *userRecord) (spawnPlan, error) {
	shell := user.Shell
	if shell == "" {
		shell = "/bin/sh"
	}
	if !filepath.IsAbs(shell) {
		return spawnPlan{}, fail(CodeKindUnavailable, fmt.Sprintf("terminal: the login shell %q of %s is not an absolute path", shell, user.Name))
	}
	return spawnPlan{
		path: shell,
		args: []string{"-" + filepath.Base(shell)},
		env:  shellEnv(user.Name, user.Home, shell),
		home: user.Home,
	}, nil
}

// shellEnv is a login shell's environment without TERM, built from scratch.
func shellEnv(name, home, shell string) []string {
	return []string{"HOME=" + home, "USER=" + name, "LOGNAME=" + name, "SHELL=" + shell, shellPath}
}

// terminal is one terminal session: the spawned process in a PTY, a reader
// goroutine copying the master's output to data records, and a waiter
// goroutine that reaps the process and, when it exited by itself, sends the
// exit record and ends the session.
type terminal struct {
	ch     *Channel
	master *os.File
	slave  *os.File
	cmd    *exec.Cmd

	ended      chan string
	exited     chan struct{} // closed once the process is reaped
	readerDone chan struct{}
	waiterDone chan struct{}

	// stopped ends the output: set by the end path and by the exit record.
	stopped atomic.Bool
	// outMu orders every data record before the exit record.
	outMu sync.Mutex
	// drained counts the bytes read after the exit; drainFull is closed when
	// it reaches maxTerminalDrain.
	drained   atomic.Int64
	drainFull chan struct{}
	drainOnce sync.Once

	endOnce sync.Once
	// halted is closed by the end path; it releases an output tap waiting on
	// a full Strict recording queue.
	halted chan struct{}
	// procMu orders the end path's signals against the exit. exitSeen is set
	// once the waiter observed the exit, before the reap; exitUnobserved is
	// set before the reap when it cannot observe it. Under either, no signal
	// names the spawned process's group, whose number may be reused.
	procMu         sync.Mutex
	exitSeen       bool
	exitUnobserved bool
	// leader is the slave's session leader recorded at the end decision, nil
	// when there is none, it is the spawned process, or it was released.
	leader *sessionLeader
	kill   *time.Timer
	// killDone is closed once the SIGKILL step ran or became unnecessary.
	killDone chan struct{}

	// observeExit blocks until the spawned process exited, without reaping it.
	observeExit func(pid int) error
	log         func(format string, args ...any)
	// rec records the session, nil when it is not recorded.
	rec *sessionRecorder
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

// startTerminal spawns plan in a new PTY of st's size. A failure after the
// spend is reported in the session: a one-line reason as data, then exit
// 127, and the kind ends the session with exited.
func startTerminal(ch *Channel, plan spawnPlan, st terminalStart, log func(string, ...any), rec *sessionRecorder) kindSession {
	master, slave, err := pty.Open()
	if err != nil {
		return startFailed(ch, err, log, rec)
	}
	if err := pty.Setsize(master, &pty.Winsize{Cols: uint16(st.Cols), Rows: uint16(st.Rows)}); err != nil {
		_ = master.Close()
		_ = slave.Close()
		return startFailed(ch, err, log, rec)
	}
	cmd := &exec.Cmd{
		Path:   plan.path,
		Args:   plan.args,
		Env:    append(slices.Clone(plan.env), "TERM="+st.Term),
		Dir:    workDir(plan.home),
		Stdin:  slave,
		Stdout: slave,
		Stderr: slave,
		// Ctty is the child's fd 0, the slave.
		SysProcAttr: &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0},
	}
	if err := cmd.Start(); err != nil {
		_ = master.Close()
		_ = slave.Close()
		return startFailed(ch, err, log, rec)
	}
	k := &terminal{
		ch: ch, master: master, slave: slave, cmd: cmd,
		ended:      make(chan string, 1),
		exited:     make(chan struct{}),
		readerDone: make(chan struct{}),
		waiterDone: make(chan struct{}),
		drainFull:  make(chan struct{}),
		killDone:   make(chan struct{}),
		halted:     make(chan struct{}),

		observeExit: observeExit,
		log:         log,
		rec:         rec,
	}
	go k.readOutput()
	go k.wait()
	return k
}

// workDir is home when it is a directory, else /.
func workDir(home string) string {
	if home != "" {
		if fi, err := os.Stat(home); err == nil && fi.IsDir() {
			return home
		}
	}
	return "/"
}

func (k *terminal) Handle(m Message) error {
	in, err := decodeTerminalInput(m)
	if err != nil {
		return err
	}
	if in.resize != nil {
		if err = pty.Setsize(k.master, &pty.Winsize{Cols: uint16(in.resize.Cols), Rows: uint16(in.resize.Rows)}); err == nil {
			k.rec.resize(uint16(in.resize.Cols), uint16(in.resize.Rows))
		}
	} else {
		_, err = k.master.Write(in.data)
	}
	if err != nil && k.over() {
		// The process exited or the session is ending; the end path reports it.
		return nil
	}
	return err
}

func (k *terminal) Ended() <-chan string { return k.ended }

func (k *terminal) End() { k.finish() }

// Wait joins the reader, the SIGKILL step and the waiter. A process still
// unreaped terminalReapTimeout after the SIGKILL (uninterruptible sleep) is
// logged and left to the waiter, which reaps it whenever it exits.
func (k *terminal) Wait() {
	<-k.readerDone
	<-k.killDone
	reap := time.NewTimer(terminalReapTimeout)
	defer reap.Stop()
	select {
	case <-k.waiterDone:
	case <-reap.C:
		k.log("session: terminal process %d not reaped %v after SIGKILL; a detached reaper owns it", k.cmd.Process.Pid, terminalReapTimeout)
	}
}

// over reports whether the process was reaped or the output stopped.
func (k *terminal) over() bool {
	select {
	case <-k.exited:
		return true
	default:
		return k.stopped.Load()
	}
}

// readOutput copies the master's output to data records until the master
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

// writeOutput sends p as one data record unless the output stopped. A failed
// write, ErrChannelClosed after the agent's close included, ends the output
// only: the session's end is decided by the server.
func (k *terminal) writeOutput(p []byte) bool {
	k.outMu.Lock()
	defer k.outMu.Unlock()
	if k.stopped.Load() {
		return false
	}
	// Recorded before the bytes reach the channel; a Strict recording may
	// hold the output up to strictBackpressure or until the end path runs.
	k.rec.output(p, k.halted)
	if k.stopped.Load() {
		return false
	}
	if err := k.ch.WriteMessage(TypeData, p); err != nil {
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

// wait reaps the process. When it exited by itself, it drains the remaining
// output, sends exit {code} and ends the session with exited.
func (k *terminal) wait() {
	defer close(k.waiterDone)
	pid := k.cmd.Process.Pid
	if err := k.observeExit(pid); err != nil {
		k.log("session: terminal: observe the exit of %d: %v", pid, err)
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
	// Held until now so the master never reads EIO while login(1) reopens
	// the tty.
	_ = k.slave.Close()
	close(k.exited)
	if k.stopped.Load() {
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
	sent := false
	if !k.stopped.Swap(true) {
		code := exitCode(k.cmd.ProcessState)
		k.rec.exit(code)
		sent = k.ch.WriteMessage(TypeExit, exitBody(code)) == nil
		if sent {
			k.ended <- CloseExited
		} else {
			k.ended <- ""
		}
	}
	k.outMu.Unlock()
	k.finish()
}

func (k *terminal) setExitSeen() {
	k.procMu.Lock()
	k.exitSeen = true
	k.procMu.Unlock()
}

// finish is the end path, run once for every end: it stops the output,
// records the slave's session leader, sends SIGHUP to the spawned process
// (login(1) forwards it to its session), hangs up the foreground group and
// the session leader where the kernel does not (macOS), arms the SIGKILL step
// at terminalKillDelay while either may be alive, revokes the slave (macOS)
// and closes the master, which hangs up the slave's session.
func (k *terminal) finish() {
	k.endOnce.Do(func() {
		k.stopped.Store(true)
		close(k.halted)
		k.procMu.Lock()
		foreground := k.foregroundGroup()
		k.leader = k.recordLeader(foreground)
		if !k.exitSeen {
			_ = k.cmd.Process.Signal(syscall.SIGHUP)
		}
		// The spawned group's number may be reused once its exit is seen.
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
			k.log("session: terminal: revoke %s: %v", k.slave.Name(), err)
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
// when the leader is the spawned process, which the group SIGKILL covers.
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
			k.log("session: terminal: hold the session leader %d: %v", sid, err)
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

// killSession is the SIGKILL step: the spawned process's group, which
// Setsid made its own, unless its exit was observed, and the recorded
// session leader. Other foreground groups are left alone.
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

// groupSignallable reports whether the spawned group may be signalled by
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

// startFailed reports a spawn failure in the session and returns a kind that
// ends it with exited.
func startFailed(ch *Channel, cause error, log func(string, ...any), rec *sessionRecorder) kindSession {
	k := &exitedKind{ended: make(chan string, 1)}
	// The cause names device paths and system errors; it stays in the
	// device's log.
	log("session: terminal did not start: %v", cause)
	const line = "localport: the terminal did not start; the device's log has the cause\r\n"
	rec.output([]byte(line), nil)
	rec.exit(terminalStartFailedCode)
	if ch.WriteMessage(TypeData, []byte(line)) == nil && ch.WriteMessage(TypeExit, exitBody(terminalStartFailedCode)) == nil {
		k.ended <- CloseExited
	} else {
		k.ended <- ""
	}
	return k
}

// exitedKind is a terminal session whose process never started. It drops
// every record until the server ends the session.
type exitedKind struct{ ended chan string }

func (exitedKind) Handle(Message) error    { return nil }
func (k *exitedKind) Ended() <-chan string { return k.ended }
func (exitedKind) End()                    {}
func (exitedKind) Wait()                   {}

//go:build linux || darwin

package cli

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"

	"github.com/localport/agent/internal/childproc"
)

// relayDrainTimeout bounds the output read after the child exited: a
// background process the child left on the PTY may keep it open.
const relayDrainTimeout = time.Second

// newExitWatch creates the child's exit watch; tests replace it.
var newExitWatch = childproc.NewWatcher

// killGroup signals the process group pid leads; tests replace it.
var killGroup = func(pid int, s syscall.Signal) error { return syscall.Kill(-pid, s) }

// runRelayed starts cmd in its own session and waits for it, as sudo with
// use_pty does: the child never shares root's terminal, so it cannot push
// input into it (TIOCSTI) or act on root's session. Each of stdin, stdout and
// stderr that is a terminal becomes, in the child, the slave of one new PTY
// (its controlling terminal); root relays bytes and the window size between
// its terminal and the master. Pipes, readers and writers stay as given.
// SIGINT and SIGTERM go to the child's process group. On terminal loss the
// group gets SIGHUP, unless hangupIgnored (root ignores SIGHUP): then root
// stops writing output, keeps draining the master and waits. Once the
// child's exit watch fails, signals go to the child alone, since its group
// number may be reused. It returns cmd.Wait's error.
func runRelayed(cmd *exec.Cmd, stdin io.Reader, stdout, stderr io.Writer, hangupIgnored bool) error {
	std := [3]any{stdin, stdout, stderr}
	var term *os.File
	ctty := -1
	for i, s := range std {
		if f, ok := s.(*os.File); ok && isTerminal(f) {
			if term == nil {
				term, ctty = f, i
			}
		}
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true
	// The child holds its own copies of cmd.ExtraFiles once it starts.
	extra := cmd.ExtraFiles
	if term == nil {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
		return runWithSignals(cmd, nil, hangupIgnored, extra...)
	}
	master, slave, err := pty.Open()
	if err != nil {
		return err
	}
	if err := pty.InheritSize(term, slave); err != nil {
		_ = master.Close()
		_ = slave.Close()
		return err
	}
	child := [3]any{stdin, stdout, stderr}
	for i, s := range std {
		if f, ok := s.(*os.File); ok && isTerminal(f) {
			child[i] = slave
		}
	}
	cmd.Stdin, _ = child[0].(io.Reader)
	cmd.Stdout, _ = child[1].(io.Writer)
	cmd.Stderr, _ = child[2].(io.Writer)
	cmd.SysProcAttr.Setctty, cmd.SysProcAttr.Ctty = true, ctty
	r := &ptyRelay{master: master, slavePath: slave.Name(), term: term, hangupIgnored: hangupIgnored}
	if child[0] == slave {
		// The input copier's cancel pipe exists before the start, so a
		// started child always has its input relayed.
		cr, cw, err := os.Pipe()
		if err != nil {
			_ = master.Close()
			_ = slave.Close()
			return err
		}
		r.input, r.cancelR, r.cancelW = term, cr, cw
	}
	return runWithSignals(cmd, r, hangupIgnored, append([]*os.File{slave}, extra...)...)
}

// runWithSignals starts cmd, forwards root's signals to its process group,
// runs the relay when there is one, and waits. closeAfterStart is closed in
// root once the child holds it.
func runWithSignals(cmd *exec.Cmd, r *ptyRelay, hangupIgnored bool, closeAfterStart ...*os.File) error {
	sigs := []os.Signal{syscall.SIGINT, syscall.SIGTERM}
	if !hangupIgnored {
		sigs = append(sigs, syscall.SIGHUP)
	}
	if r != nil {
		sigs = append(sigs, syscall.SIGWINCH)
	}
	sig := make(chan os.Signal, 4)
	signal.Notify(sig, sigs...)
	defer signal.Stop(sig)
	watch, err := childproc.StartWatched(cmd, newExitWatch, (*exec.Cmd).Start, killGroup)
	for _, f := range closeAfterStart {
		_ = f.Close()
	}
	if err != nil {
		if r != nil {
			r.closeUnstarted()
		}
		return err
	}
	if r != nil && r.input != nil {
		// Raw only once the child runs, so a failed start leaves the terminal
		// as it was; restored on every return after this.
		restore, err := makeRaw(r.input)
		if err != nil {
			// The child leads its own group and is unreaped, so the group's
			// number is still its own.
			_ = killGroup(cmd.Process.Pid, syscall.SIGKILL)
			_ = cmd.Wait()
			_ = watch.Close()
			r.closeUnstarted()
			return err
		}
		defer restore()
	}
	pid := cmd.Process.Pid
	var exitMu sync.Mutex
	// exited is set once the exit is observed or the child reaped;
	// unobserved before the reap when the watch failed.
	exited, unobserved := false, false
	// group signals the child's process group while it is unreaped and its
	// exit observable, so a reused group number is never signalled; with the
	// exit unobservable, only the child.
	group := func(s syscall.Signal) {
		exitMu.Lock()
		defer exitMu.Unlock()
		switch {
		case exited:
		case unobserved:
			_ = cmd.Process.Signal(s)
		default:
			_ = killGroup(pid, s)
		}
	}
	if r != nil {
		r.hangup = func() { group(syscall.SIGHUP) }
		r.start()
	}
	done := make(chan error, 1)
	go func() {
		err := watch.Wait()
		exitMu.Lock()
		if err == nil {
			exited = true
		} else {
			unobserved = true
		}
		exitMu.Unlock()
		// Closed after the decision, so a closed watch implies it is recorded.
		_ = watch.Close()
		waitErr := cmd.Wait()
		exitMu.Lock()
		exited = true
		exitMu.Unlock()
		done <- errors.Join(err, waitErr)
	}()
	for {
		select {
		case s := <-sig:
			switch s {
			case syscall.SIGWINCH:
				_ = pty.InheritSize(r.term, r.master)
			case syscall.SIGHUP:
				if r != nil {
					r.lost()
				} else {
					group(syscall.SIGHUP)
				}
			default:
				group(s.(syscall.Signal))
			}
		case err := <-done:
			if r != nil {
				r.finish()
			}
			return err
		}
	}
}

// ptyRelay copies between root's terminal and the PTY master.
type ptyRelay struct {
	master    *os.File
	slavePath string
	term      *os.File
	// input is the terminal root reads input from, nil when stdin is not
	// one; it is in raw mode while the relay runs.
	input         *os.File
	hangupIgnored bool
	hangup        func()

	lostOnce   sync.Once
	termLost   chan struct{}
	outputDone chan struct{}
	inputDone  chan struct{}
	cancelR    *os.File
	cancelW    *os.File
}

func (r *ptyRelay) start() {
	r.termLost = make(chan struct{})
	r.outputDone = make(chan struct{})
	go r.copyOutput()
	if r.input == nil {
		return
	}
	r.inputDone = make(chan struct{})
	go r.copyInput()
}

// closeUnstarted releases a relay whose child never ran.
func (r *ptyRelay) closeUnstarted() {
	_ = r.master.Close()
	if r.cancelR != nil {
		_ = r.cancelR.Close()
		_ = r.cancelW.Close()
	}
}

// lost records the terminal's loss once: output stops reaching it and,
// unless root ignores SIGHUP, the child's group gets SIGHUP.
func (r *ptyRelay) lost() {
	r.lostOnce.Do(func() {
		close(r.termLost)
		if !r.hangupIgnored {
			r.hangup()
		}
	})
}

func (r *ptyRelay) isLost() bool {
	select {
	case <-r.termLost:
		return true
	default:
		return false
	}
}

// copyOutput writes the master's output to the terminal until the master
// ends; after the terminal is lost it keeps reading and drops the output,
// so the child never blocks on a full PTY.
func (r *ptyRelay) copyOutput() {
	defer close(r.outputDone)
	buf := make([]byte, 32<<10)
	for {
		n, err := r.master.Read(buf)
		if n > 0 && !r.isLost() {
			if _, werr := r.term.Write(buf[:n]); werr != nil {
				r.lost()
			}
		}
		if err != nil {
			return
		}
	}
}

// copyInput writes what root's terminal reads to the master until the
// terminal ends (its loss) or finish cancels it.
func (r *ptyRelay) copyInput() {
	defer close(r.inputDone)
	in, cancel := int(r.input.Fd()), int(r.cancelR.Fd())
	buf := make([]byte, 4<<10)
	for {
		fds := []unix.PollFd{{Fd: int32(in), Events: unix.POLLIN}, {Fd: int32(cancel), Events: unix.POLLIN}}
		if _, err := unix.Poll(fds, -1); err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			r.lost()
			return
		}
		if fds[1].Revents != 0 {
			return
		}
		n, err := unix.Read(in, buf)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		if n <= 0 {
			r.lost()
			return
		}
		if _, err := r.master.Write(buf[:n]); err != nil {
			return
		}
	}
}

// finish runs after the child exited: it drains the master for at most
// relayDrainTimeout, ends it (a revoke first, which macOS needs to end a
// blocked Read) and joins both copiers.
func (r *ptyRelay) finish() {
	t := time.NewTimer(relayDrainTimeout)
	select {
	case <-r.outputDone:
	case <-t.C:
	}
	t.Stop()
	_ = childproc.RevokeTTY(r.slavePath)
	_ = r.master.Close()
	<-r.outputDone
	if r.inputDone != nil {
		_ = r.cancelW.Close()
		<-r.inputDone
		_ = r.cancelR.Close()
	}
}

func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), ioctlReadTermios)
	return err == nil
}

// makeRaw puts f in raw mode, as cfmakeraw: every byte, ^C included, goes to
// the child's PTY, whose own line discipline applies it. restore puts the
// original mode back.
func makeRaw(f *os.File) (restore func(), err error) {
	fd := int(f.Fd())
	orig, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		return nil, err
	}
	raw := *orig
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Oflag &^= unix.OPOST
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, ioctlWriteTermios, &raw); err != nil {
		return nil, err
	}
	return func() { _ = unix.IoctlSetTermios(fd, ioctlWriteTermios, orig) }, nil
}

//go:build cgo && (linux || darwin)

package sessionhelper

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/localport/agent/internal/launcher"
)

// fakeWatch is an exit watch whose registration or wait fails on demand. It
// records the pid it was given.
type fakeWatch struct {
	watchErr, waitErr error
	pid               int
}

func (w *fakeWatch) Watch(pid int) error { w.pid = pid; return w.watchErr }
func (w *fakeWatch) Wait() error         { return w.waitErr }
func (w *fakeWatch) Close() error        { return nil }

// setExitWatch makes every session start in the test use newWatch.
func setExitWatch(t *testing.T, newWatch func() (exitWatch, error)) {
	t.Helper()
	old := newExitWatch
	newExitWatch = newWatch
	t.Cleanup(func() { newExitWatch = old })
}

// groupSignals records every signal sent to a process group by number.
type groupSignals struct {
	mu   sync.Mutex
	sent []syscall.Signal
}

func recordGroupSignals(t *testing.T) *groupSignals {
	t.Helper()
	g := &groupSignals{}
	old := killGroup
	killGroup = func(pid int, s syscall.Signal) error {
		g.mu.Lock()
		g.sent = append(g.sent, s)
		g.mu.Unlock()
		return old(pid, s)
	}
	t.Cleanup(func() { killGroup = old })
	return g
}

func (g *groupSignals) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.sent)
}

// startPipeFails starts command on pipes and requires the start to fail.
func startPipeFails(t *testing.T, command string) {
	t.Helper()
	_, helper := pollablePair(t)
	defer helper.Close()
	plan := spawnPlan{path: "/bin/sh", args: []string{"sh", "-c", command}, env: []string{"PATH=/usr/bin:/bin"}, dir: "/"}
	if p, err := startPipeSession(&frameWriter{w: helper}, plan, t.Logf); err == nil {
		p.finish()
		p.Wait()
		t.Fatal("the session started")
	}
}

// startTerminalFails starts command on a PTY and requires the start to fail.
func startTerminalFails(t *testing.T, command string) {
	t.Helper()
	_, helper := pollablePair(t)
	defer helper.Close()
	master, slave, err := openPTY(80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	plan := spawnPlan{path: "/bin/sh", args: []string{"sh", "-c", command}, env: []string{"PATH=/usr/bin:/bin"}, dir: "/"}
	if k, err := startTerminal(&frameWriter{w: helper}, master, slave, plan, t.Logf); err == nil {
		k.finish()
		k.Wait()
		t.Fatal("the session started")
	}
}

// Without an exit watch no session child is spawned.
func TestSessionStartRefusedWithoutAnExitWatch(t *testing.T) {
	setExitWatch(t, func() (exitWatch, error) { return nil, unix.EMFILE })
	for name, start := range map[string]func(*testing.T, string){"pipe": startPipeFails, "terminal": startTerminalFails} {
		t.Run(name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "ran")
			start(t, "touch "+marker)
			time.Sleep(200 * time.Millisecond)
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the command ran: %v", err)
			}
		})
	}
}

// A child whose exit cannot be registered is killed and reaped; the start fails.
func TestSessionStartRefusedWhenTheWatchFails(t *testing.T) {
	for name, start := range map[string]func(*testing.T, string){"pipe": startPipeFails, "terminal": startTerminalFails} {
		t.Run(name, func(t *testing.T) {
			w := &fakeWatch{watchErr: unix.ENOMEM}
			setExitWatch(t, func() (exitWatch, error) { return w, nil })
			start(t, "sleep 30")
			if w.pid == 0 {
				t.Fatal("the watch was never registered")
			}
			// Reaped: the pid no longer names a process of the test.
			if err := syscall.Kill(w.pid, 0); !errors.Is(err, syscall.ESRCH) {
				t.Fatalf("child %d after the refused start: %v", w.pid, err)
			}
		})
	}
}

// startPipeUnwatched is startPipeAgent with an exit watch whose Wait fails at
// once, as an unobservable exit.
func startPipeUnwatched(t *testing.T, command string, park byte) (*pipeSession, *os.File, *gateWriter) {
	t.Helper()
	setExitWatch(t, func() (exitWatch, error) { return &fakeWatch{waitErr: unix.EBADF}, nil })
	return startPipeAgent(t, command, park)
}

// With the exit unobservable, a command still running keeps delivering its
// output past terminalDrainTimeout, and the exit frame carries its status.
func TestPipeSessionUnobservedExitKeepsTheOutput(t *testing.T) {
	_, agent, _ := startPipeUnwatched(t, "sleep 1.5; echo late; exit 7", 0)
	fr := launcher.NewFrameReader(agent)
	stdout, _, code := readToExit(t, fr)
	if stdout != "late\n" || code != 7 {
		t.Fatalf("stdout %q, exit %d; want %q, 7", stdout, code, "late\n")
	}
}

// With the exit unobservable, a command that exits while its output is
// parked still releases the login, then delivers its output and its status.
func TestPipeSessionUnobservedExitReleasesTheLogin(t *testing.T) {
	p, agent, gate := startPipeUnwatched(t, "read x; echo hi; exit 3", launcher.FrameData)
	e := startEnding(t, p, p.out)
	if err := p.handle(launcher.Frame{Type: launcher.FrameData, Data: []byte("go\n")}); err != nil {
		t.Fatal(err)
	}
	gate.waitParked(t)
	// At the reap, well before endExitWait would release it anyway.
	select {
	case <-e.released:
	case <-time.After(endExitWait / 2):
		t.Fatal("the login was not released at the reap with the output parked")
	}
	gate.release()
	waitClosed(t, "endSession returned", e.done)
	fr := launcher.NewFrameReader(agent)
	stdout, _, code := readToExit(t, fr)
	if stdout != "hi\n" || code != 3 {
		t.Fatalf("stdout %q, exit %d; want %q, 3", stdout, code, "hi\n")
	}
}

// With the exit unobservable, the end path signals only the command, never
// its group by number, and still ends it.
func TestPipeSessionUnobservedExitSignalsOnlyTheCommand(t *testing.T) {
	groups := recordGroupSignals(t)
	p, _, _ := startPipeUnwatched(t, "trap '' HUP; while :; do sleep 0.1; done", 0)
	time.Sleep(100 * time.Millisecond)
	p.finish()
	done := make(chan struct{})
	go func() { p.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(terminalKillDelay + 5*time.Second):
		t.Fatal("Wait did not return after the SIGKILL")
	}
	if n := groups.count(); n != 0 {
		t.Fatalf("%d group signals with the exit unobservable; want 0", n)
	}
}

// pollableFile gives Run's channel a descriptor that takes a write deadline,
// which bounds the output after the end.
func TestPollableFileTakesAWriteDeadline(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	f, err := pollableFile(fds[0], "channel")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("write deadline: %v", err)
	}
}

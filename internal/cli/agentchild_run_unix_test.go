//go:build !windows

package cli

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/launcher"
)

// fakeEndpoint is a listening socket standing in for the control endpoint;
// closed records whether run.lock was still held when root closed it, and
// starting whether root answers that the run is starting.
type fakeEndpoint struct {
	ln          *net.UnixListener
	file        *os.File
	path        string
	lockFile    config.LocalConfigFile
	closed      bool
	heldAtClose bool
	starting    bool
	heldAtStart bool
}

func (e *fakeEndpoint) File() *os.File { return e.file }

func (e *fakeEndpoint) ServeStarting(func(string, ...any)) (func(), error) {
	_, err := config.LockRun(e.lockFile, 0)
	e.starting, e.heldAtStart = true, errors.Is(err, config.ErrRunLocked)
	return func() { e.starting = false }, nil
}

func (e *fakeEndpoint) Close() error {
	release, err := config.LockRun(e.lockFile, 0)
	if err == nil {
		_ = release()
	}
	e.closed, e.heldAtClose = true, errors.Is(err, config.ErrRunLocked)
	_ = e.file.Close()
	_ = e.ln.Close()
	return os.Remove(e.path)
}

// relayedRunSeams points openControl and runAgentWith at fakes for the test.
func relayedRunSeams(t *testing.T, file config.LocalConfigFile, child func(extra []*os.File) error) (opened *int, endpoint **fakeEndpoint) {
	t.Helper()
	prevOpen, prevRun := openControl, runAgentWith
	t.Cleanup(func() { openControl, runAgentWith = prevOpen, prevRun })
	var count int
	var ep *fakeEndpoint
	openControl = func() (controlEndpoint, error) {
		count++
		dir, err := os.MkdirTemp("", "ctl")
		if err != nil {
			return nil, err
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		path := filepath.Join(dir, "control.sock")
		ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			return nil, err
		}
		ln.SetUnlinkOnClose(false)
		f, err := ln.File()
		if err != nil {
			return nil, err
		}
		ep = &fakeEndpoint{ln: ln, file: f, path: path, lockFile: file}
		return ep, nil
	}
	runAgentWith = func(_ []string, _ io.Reader, _ io.Writer, extra []*os.File) error {
		defer func() {
			for _, f := range extra {
				_ = f.Close()
			}
		}()
		return child(extra)
	}
	return &count, &ep
}

// A descriptor root passed is close-on-exec once the child takes it, so no
// process the child starts inherits the control socket or run.lock.
func TestInheritedDescriptorIsCloseOnExec(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	// A copy without close-on-exec, as exec leaves an inherited descriptor.
	fd, err := unix.Dup(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	f := inheritedDescriptor(uintptr(fd), "inherited")
	defer f.Close()
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("inherited descriptor flags %#x, %v; want close-on-exec", flags, err)
	}
}

// A run root relays as the agent account adopts the run.lock root passed
// instead of taking it, and serves the control socket root passed instead of
// opening its own.
func TestRelayedChildUsesTheInheritedLockAndSocket(t *testing.T) {
	file := asRoot(t, &fakeManager{})
	prevChild, prevLockFD, prevCtlFD, prevListen := asAgentChild, runLockFD, controlSocketFD, listenControl
	t.Cleanup(func() {
		asAgentChild, runLockFD, controlSocketFD, listenControl = prevChild, prevLockFD, prevCtlFD, prevListen
	})
	asAgentChild = true
	listenControl = func() (*launcher.ControlListener, error) {
		t.Error("the child opened a control endpoint of its own")
		return nil, errors.New("not the inherited socket")
	}
	// Root's run.lock, held by this test, and a duplicate for the child.
	lock, release, err := config.LockRunFile(context.Background(), file, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = release() }()
	lockDup, err := unix.Dup(int(lock.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	runLockFD = uintptr(lockDup)
	// Not a socket: the inherited endpoint is refused, which ends the run
	// after the lock was adopted.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	defer r.Close()
	// A duplicate: inheritedControl takes and closes the descriptor it gets.
	ctlDup, err := unix.Dup(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	controlSocketFD = uintptr(ctlDup)

	err = runEnrolledDevices(context.Background(), "test", currentInvoker(true), false, true, func() {})
	if errors.Is(err, config.ErrRunLocked) {
		t.Fatalf("child run = %v: it took run.lock instead of adopting root's", err)
	}
	if !errors.Is(err, errcode.New(errcode.ControlEndpointFailed)) {
		t.Fatalf("child run with a non-socket descriptor = %v, want AG160 from the inherited endpoint", err)
	}
}

// Root takes run.lock before it opens the control endpoint, answers that the
// run is starting under the lock, stops answering before the child starts,
// passes the listening socket and a copy of the lock the child can adopt, and
// removes the socket while run.lock is still held; a run refused run.lock
// opens no endpoint.
func TestRelayedRunPassesTheEndpointUnderTheRunLock(t *testing.T) {
	file := asRoot(t, &fakeManager{})
	var adopted error
	listening, rootAnswering := false, false
	var ep **fakeEndpoint
	var opened *int
	opened, ep = relayedRunSeams(t, file, func(extra []*os.File) error {
		if len(extra) != 2 {
			t.Fatalf("child got %d descriptors, want the socket and run.lock", len(extra))
		}
		listening = extra[0] == (*ep).file
		rootAnswering = (*ep).starting
		adopted = config.AdoptRunLock(file, extra[1])
		return nil
	})

	if err := runRunAsAgent([]string{"run"}, nil, io.Discard); err != nil {
		t.Fatal(err)
	}
	if *opened != 1 || !listening || adopted != nil {
		t.Fatalf("opened %d, socket passed %v, adopt run.lock: %v; want one endpoint passed with an adoptable run.lock", *opened, listening, adopted)
	}
	if !(*ep).heldAtStart || rootAnswering {
		t.Fatalf("root answered starting under run.lock %v, still answering when the child started %v; want under the lock and stopped before the child", (*ep).heldAtStart, rootAnswering)
	}
	if !(*ep).closed || !(*ep).heldAtClose {
		t.Fatalf("endpoint closed %v, run.lock held at close %v; want it removed under run.lock", (*ep).closed, (*ep).heldAtClose)
	}
	release, err := config.LockRun(file, 0)
	if err != nil {
		t.Fatalf("run.lock after the run: %v, want it released", err)
	}

	err = runRunAsAgent([]string{"run"}, nil, io.Discard)
	if !errors.Is(err, config.ErrRunLocked) || *opened != 1 {
		t.Fatalf("run beside a holder = %v, endpoints opened %d; want ErrRunLocked and none", err, *opened)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

//go:build !windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/service"
)

// runAsAgentAccount re-executes this binary as the agent account with
// agentChildCommand and args, stdin and stdout as given and stderr shared,
// in its own session behind a PTY relay when any of them is a terminal
// (runRelayed). A child that fails has printed its own error; the result is
// a service.ExitError with its status.
func runAsAgentAccount(args []string, stdin io.Reader, stdout io.Writer) error {
	return runAsAgentAccountWith(args, stdin, stdout, nil)
}

// runAsAgentAccountWith is runAsAgentAccount with extra as the child's
// descriptors 3 and on; this process closes its copies once the child starts,
// or on any failure before that.
func runAsAgentAccountWith(args []string, stdin io.Reader, stdout io.Writer, extra []*os.File) error {
	defer func() {
		for _, f := range extra {
			_ = f.Close()
		}
	}()
	acct, err := service.LookupAccount()
	if err != nil {
		return err
	}
	exe, err := service.Executable()
	if err != nil {
		return err
	}
	cmd := agentChildCmd(exe, acct, args)
	cmd.ExtraFiles = extra
	err = runRelayed(cmd, stdin, stdout, os.Stderr, signal.Ignored(syscall.SIGHUP))
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		code := exitErr.ExitCode()
		if code <= 0 {
			code = 1
		}
		return &service.ExitError{Code: code, Err: errcode.New(errcode.AgentChildFailed).With(nil, fmt.Sprintf("localport %s", args[0]))}
	case err != nil && cmd.Process == nil:
		return errcode.New(errcode.AgentChildStart).With(err, "")
	}
	return err
}

// agentChildCmd is the child's command: fixed argv (--verbose first when
// set, so the child prints its error the same way), no environment, the
// root directory, and the agent account's uid, gid and only group.
func agentChildCmd(exe string, acct service.Account, args []string) *exec.Cmd {
	argv := []string{agentChildCommand}
	if verbose {
		argv = []string{"--verbose", agentChildCommand}
	}
	cmd := exec.Command(exe, append(argv, args...)...)
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid:    uint32(acct.UID),
		Gid:    uint32(acct.GID),
		Groups: []uint32{uint32(acct.GID)},
	}}
	return cmd
}

// runRunAsAgent runs `run` args as the agent account. A foreground run takes
// run.lock here, as every privileged run does, and is started under it
// (runHeldAsAgent). A run that ends at its flags (help, a flag error) and
// `run --service` are relayed as they are; the service takes run.lock in the
// child.
func runRunAsAgent(args []string, stdin io.Reader, stdout io.Writer) (retErr error) {
	if !runServesInForeground(args[1:]) {
		return runAsAgentAccount(args, stdin, stdout)
	}
	file, err := systemLocalConfig()
	if err != nil {
		return err
	}
	lock, release, err := holdRunLock(context.Background(), file, "localport run", false)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, release()) }()
	ctl, err := openStartingControl()
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, ctl.Close()) }()
	return runHeldAsAgent(args, stdin, stdout, lock, ctl)
}

// runAgentWith is runAsAgentAccountWith; tests replace it.
var runAgentWith = runAsAgentAccountWith

// controlEndpoint is the listening control socket root opens and passes to
// the child (launcher.ControlSocket).
type controlEndpoint interface {
	File() *os.File
	ServeStarting(logf func(format string, args ...any)) (stop func(), err error)
	Close() error
}

// startingControl is the control socket root opens right after it takes
// run.lock, answering that the run is starting until runHeldAsAgent hands it
// to the child.
type startingControl struct {
	sock controlEndpoint
	stop func()
}

// openStartingControl opens the control socket (openControl) and answers that
// the run is starting on it, so up, down and set reach the run while root
// enrols. The caller holds run.lock and closes the result before releasing it.
func openStartingControl() (*startingControl, error) {
	sock, err := openControl()
	if err != nil {
		return nil, controlEndpointFailed(err)
	}
	stop, err := sock.ServeStarting(logEventf)
	if err != nil {
		return nil, errors.Join(controlEndpointFailed(err), sock.Close())
	}
	return &startingControl{sock: sock, stop: stop}, nil
}

// Close stops answering and removes the socket.
func (c *startingControl) Close() error {
	c.stop()
	return c.sock.Close()
}

// openControl is launcher.OpenControl; tests replace it.
var openControl = func() (controlEndpoint, error) {
	sock, err := launcher.OpenControl()
	if err != nil {
		return nil, err
	}
	return sock, nil
}

// runHeldAsAgent runs the foreground run args as the agent account under
// lock, the run lock descriptor this process holds (config.LockRunFile: the
// device config directory), with socket activation of the
// control endpoint ctl: it stops answering on ctl and passes the listening
// socket and a duplicate of lock as the child's descriptors controlSocketFD
// and runLockFD, closing its own copies once the child starts. A client that
// connects before the child accepts waits in the backlog. The caller closes
// ctl after the child exits, which removes the socket, and then releases
// run.lock, so the path is never removed under another run.
func runHeldAsAgent(args []string, stdin io.Reader, stdout io.Writer, lock *os.File, ctl *startingControl) error {
	fd, err := unix.FcntlInt(lock.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return errcode.New(errcode.AgentChildStart).With(err, "pass run.lock")
	}
	ctl.stop()
	return runAgentWith(args, stdin, stdout, []*os.File{ctl.sock.File(), os.NewFile(uintptr(fd), lock.Name())})
}

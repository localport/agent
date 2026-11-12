//go:build !windows

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/service"
)

// runAsAgentAccount re-executes this binary as the agent account with
// agentChildCommand and args, stdin and stdout as given and stderr shared,
// in its own session behind a PTY relay when any of them is a terminal
// (runRelayed). A child that fails has printed its own error; the result is
// a service.ExitError with its status.
func runAsAgentAccount(args []string, stdin io.Reader, stdout io.Writer) error {
	acct, err := service.LookupAccount()
	if err != nil {
		return err
	}
	exe, err := service.Executable()
	if err != nil {
		return err
	}
	cmd := agentChildCmd(exe, acct, args)
	err = runRelayed(cmd, stdin, stdout, os.Stderr, signal.Ignored(syscall.SIGHUP))
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		code := exitErr.ExitCode()
		if code <= 0 {
			code = 1
		}
		return &service.ExitError{Code: code, Err: fmt.Errorf("%w: localport %s", errcode.New(errcode.AgentChildFailed), args[0])}
	case err != nil && cmd.Process == nil:
		return fmt.Errorf("%w: %w", errcode.New(errcode.AgentChildStart), err)
	}
	return err
}

// agentChildCmd is the child's command: fixed argv, no environment, the
// root directory, and the agent account's uid, gid and only group.
func agentChildCmd(exe string, acct service.Account, args []string) *exec.Cmd {
	cmd := exec.Command(exe, append([]string{agentChildCommand}, args...)...)
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid:    uint32(acct.UID),
		Gid:    uint32(acct.GID),
		Groups: []uint32{uint32(acct.GID)},
	}}
	return cmd
}

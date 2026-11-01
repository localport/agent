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

	"github.com/localport/agent/internal/service"
)

// runAsAgentAccount re-executes this binary as the agent account with
// agentChildCommand and args, stdin and stdout as given and stderr shared. A
// SIGTERM or SIGHUP root receives is forwarded; SIGINT from the terminal
// reaches the child directly, as both are in its foreground process group.
// A child that fails has printed its own error; the result is a
// service.ExitError with its status.
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
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, os.Stderr
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sig)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start localport as the account %s: %w", service.AgentAccount, err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	for {
		select {
		case s := <-sig:
			if s != syscall.SIGINT {
				_ = cmd.Process.Signal(s)
			}
		case err := <-done:
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				code := exitErr.ExitCode()
				if code <= 0 {
					code = 1
				}
				return &service.ExitError{Code: code, Err: fmt.Errorf("localport %s, run as the account %s, failed", args[0], service.AgentAccount)}
			}
			return err
		}
	}
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

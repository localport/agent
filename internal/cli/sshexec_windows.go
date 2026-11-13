package cli

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"

	"github.com/localport/agent/internal/errcode"
)

// execSSH runs ssh on this console and exits with its status; Windows has no
// exec. Ctrl-C reaches ssh through the shared console, so this process
// ignores it while ssh runs.
func execSSH(path string, argv []string) error {
	cmd := exec.Command(path, argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	signal.Ignore(os.Interrupt)
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		os.Exit(exit.ExitCode())
	}
	if err != nil {
		return errcode.New(errcode.OpenSSHUnavailable).With(err, "run "+path)
	}
	os.Exit(0)
	return nil
}

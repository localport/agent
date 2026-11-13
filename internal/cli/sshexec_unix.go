//go:build unix

package cli

import (
	"os"
	"syscall"

	"github.com/localport/agent/internal/errcode"
)

// execSSH replaces this process with ssh, so signals, the terminal and the
// exit status are ssh's own.
func execSSH(path string, argv []string) error {
	if err := syscall.Exec(path, argv, os.Environ()); err != nil {
		return errcode.New(errcode.OpenSSHUnavailable).With(err, "run "+path)
	}
	return nil
}

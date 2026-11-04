//go:build unix

package cli

import (
	"fmt"
	"os"
	"syscall"
)

// execSSH replaces this process with ssh, so signals, the terminal and the
// exit status are ssh's own.
func execSSH(path string, argv []string) error {
	if err := syscall.Exec(path, argv, os.Environ()); err != nil {
		return fmt.Errorf("run %s: %w", path, err)
	}
	return nil
}

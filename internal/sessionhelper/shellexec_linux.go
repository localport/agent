//go:build cgo && linux

package sessionhelper

import (
	"fmt"
	"io"
)

// disclaimAvailable is false: TCC responsibility is a macOS concept, and no
// Linux session carries a Full Disk Access reading that would ask for it.
func disclaimAvailable() bool { return false }

// ShellExec refuses: the shell-exec mode exists on macOS only.
func ShellExec(_ []string, stderr io.Writer) int {
	fmt.Fprintln(stderr, "localport: shell-exec: not supported on this platform")
	return 127
}

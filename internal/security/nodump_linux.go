//go:build linux

package security

import (
	"os"

	"golang.org/x/sys/unix"
)

// HardenProcess marks the process non-dumpable with PR_SET_DUMPABLE. The agent
// keeps its bearer token in memory for reconnects. This disables core dumps
// and same-user ptrace and /proc/<pid>/mem access. Only root can attach.
//
// Set LOCALPORT_ALLOW_COREDUMP=1 to stay dumpable for debugging. Errors are
// ignored.
func HardenProcess() {
	if os.Getenv("LOCALPORT_ALLOW_COREDUMP") == "1" {
		return
	}
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

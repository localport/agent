//go:build unix

package session

import (
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// signalName is signal n's name without SIG, "" when it has none.
func signalName(n int) string {
	return strings.TrimPrefix(unix.SignalName(syscall.Signal(n)), "SIG")
}

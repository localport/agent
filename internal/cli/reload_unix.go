//go:build !windows

package cli

import (
	"os"
	"os/signal"
	"syscall"
)

// reloadSignals delivers SIGHUP, which the service managers send on reload.
func reloadSignals() (<-chan os.Signal, func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	return sig, func() { signal.Stop(sig) }
}

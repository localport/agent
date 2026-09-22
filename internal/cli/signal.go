package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// forcedExitStatus is the shell exit status of a process killed by SIGINT.
const forcedExitStatus = 130

// signalContext cancels on the first SIGINT or SIGTERM and exits on the
// second, so a stalled shutdown can still be interrupted. onFirst runs before
// the cancel, for example to restore the terminal.
func signalContext(onFirst func()) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())

	// Buffer two. The second signal can arrive between the two receives.
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sig
		if onFirst != nil {
			onFirst()
		}
		cancel()
		<-sig
		os.Exit(forcedExitStatus)
	}()

	return ctx, func() {
		signal.Stop(sig)
		cancel()
	}
}

package cli

import (
	"context"
	"os"
	"os/signal"
	"sync"
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

	// stopped ends the goroutine when the caller stops listening.
	stopped := make(chan struct{})
	go func() {
		select {
		case <-sig:
		case <-stopped:
			return
		}
		if onFirst != nil {
			onFirst()
		}
		cancel()
		select {
		case <-sig:
			os.Exit(forcedExitStatus)
		case <-stopped:
		}
	}()

	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			signal.Stop(sig)
			close(stopped)
			cancel()
		})
	}
}

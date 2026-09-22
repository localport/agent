//go:build unix

// These tests signal the test process with syscall.Kill and SIGUSR1, which
// Windows lacks.

package cli

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

// The first signal cancels and the second is still received.
func TestSignalContextCancelsOnFirstSignalAndRunsOnFirst(t *testing.T) {
	ran := make(chan struct{})
	ctx, stop := signalContext(func() { close(ran) })
	defer stop()

	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("raise SIGINT: %v", err)
	}

	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("onFirst never ran")
	}
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the context was not cancelled")
	}
}

// stop unregisters the handler so later signals get the default disposition.
func TestSignalContextStopUnregisters(t *testing.T) {
	_, stop := signalContext(nil)
	stop()

	// Passes if the test neither hangs nor exits the test binary.
	ignored := make(chan os.Signal, 1)
	signal.Notify(ignored, syscall.SIGUSR1)
	defer signal.Stop(ignored)
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatalf("raise SIGUSR1: %v", err)
	}
	select {
	case <-ignored:
	case <-time.After(2 * time.Second):
		t.Fatal("signal delivery is broken in this environment")
	}
}

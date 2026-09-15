//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd

package netmon

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

// Close interrupts a blocked watch through the runtime poller.
func TestSourceCloseUnblocksAParkedWatch(t *testing.T) {
	src := newSource(slog.New(slog.DiscardHandler))
	if src == nil {
		t.Skip("no kernel event source available here")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		src.watch(context.Background(), make(chan struct{}, 1))
	}()

	// Let watch reach its blocking read before Close.
	time.Sleep(100 * time.Millisecond)
	if err := src.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not unblock a watch parked in Read")
	}
}

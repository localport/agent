package tunnel

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/localport/agent/internal/proto"
)

// Cancelling the context ends the session promptly. The loops select on
// shutdown and disconnected, so runSession must signal them.
func TestRunSessionEndsPromptlyOnContextCancel(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	tn := New(Options{Token: "tok", Edge: "connect.eu.localport.dev:443", Local: "127.0.0.1:1"})
	tn.mu.Lock()
	tn.raw = a
	tn.conn = proto.NewConn(a)
	tn.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tn.runSession(ctx, tn.disconnected)
	}()

	// Let both loops park before the cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Well under sessionDrainTimeout.
	const budget = 250 * time.Millisecond
	started := time.Now()
	select {
	case <-done:
	case <-time.After(budget):
		t.Fatalf("runSession did not return within %s of the cancel", budget)
	}
	t.Logf("runSession returned %s after the cancel", time.Since(started).Round(time.Millisecond))
}

package cli

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// The outliving runs keep running until stop, which cancels their context
// and returns only after every run returned; a second stop is a no-op.
func TestRunOutlivingStopsAndWaits(t *testing.T) {
	var started, returned atomic.Int32
	run := func(ctx context.Context) {
		started.Add(1)
		<-ctx.Done()
		time.Sleep(20 * time.Millisecond)
		returned.Add(1)
	}
	stop := runOutliving(run, run)
	deadline := time.Now().Add(3 * time.Second)
	for started.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the runs did not start")
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	if returned.Load() != 0 {
		t.Fatal("a run returned before stop")
	}
	stop()
	if returned.Load() != 2 {
		t.Fatalf("stop returned with %d of 2 runs done", returned.Load())
	}
	stop()
}

//go:build linux || darwin

package launcher

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// countingTicks is a revocation ticker the test drives: each started watcher
// takes ticks from ch and counts its start and its stop.
type countingTicks struct {
	ch chan time.Time
	// starts receives once per started watcher, stopping once per stop.
	starts, stopping chan struct{}
	// stopGate, when set before a watcher starts, holds that watcher's stop
	// until it closes.
	stopGate chan struct{}

	mu               sync.Mutex
	started, stopped int
}

func newCountingTicks() *countingTicks {
	return &countingTicks{ch: make(chan time.Time), starts: make(chan struct{}, 8), stopping: make(chan struct{}, 8)}
}

func (c *countingTicks) ticker(time.Duration) (<-chan time.Time, func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.started++
	gate := c.stopGate
	c.starts <- struct{}{}
	return c.ch, func() {
		c.stopping <- struct{}{}
		if gate != nil {
			<-gate
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		c.stopped++
	}
}

func (c *countingTicks) counts() (started, stopped int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.started, c.stopped
}

// close joins the watcher, and a session registered after it starts none; a
// later open starts one for the sessions still registered, which ends them at
// a denied reading.
func TestRevocationCloseJoinsAndOpenRestarts(t *testing.T) {
	ticks := newCountingTicks()
	r := newRevocation(func() string { return FullDiskAccessDenied }, t.Logf)
	r.ticker = ticks.ticker

	// The first watcher's stop blocks until release closes: close must not
	// return before the watcher has ended.
	release := make(chan struct{})
	ticks.stopGate = release
	r.open(context.Background())
	first := &grantedSession{control: devNull(t)}
	r.add(context.Background(), first)
	<-ticks.starts
	closed := make(chan struct{})
	go func() { r.close(); close(closed) }()
	<-ticks.stopping
	select {
	case <-closed:
		t.Fatal("close returned while the watcher was still stopping")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	<-closed
	ticks.stopGate = nil

	theirs, ours := pipe(t)
	second := &grantedSession{control: ours}
	r.add(context.Background(), second)
	r.mu.Lock()
	running := r.stop != nil
	r.mu.Unlock()
	if running {
		t.Fatal("add after close started a watcher")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.open(ctx)
	select {
	case <-ticks.starts:
	case <-time.After(10 * time.Second):
		t.Fatal("open with a registered session started no watcher")
	}
	ticks.ch <- time.Now()
	_ = theirs.SetReadDeadline(time.Now().Add(10 * time.Second))
	if reason, err := ReadHelperEnd(theirs); err != nil || reason != EndFullDiskAccessRevoked {
		t.Fatalf("second session got %q, %v; want the revoked end", reason, err)
	}
	r.remove(first)
	r.remove(second)
	r.close()
	if started, stopped := ticks.counts(); stopped != started {
		t.Fatalf("%d watchers started, %d stopped", started, stopped)
	}
}

// An end whose control channel its run goroutine already closed is the normal
// race of a revocation with a session's end and logs nothing.
func TestRevocationEndOnClosedControlIsQuiet(t *testing.T) {
	_, ours := pipe(t)
	_ = ours.Close()
	var logged []string
	(&grantedSession{control: ours}).end(func(format string, args ...any) {
		logged = append(logged, format)
	})
	if len(logged) != 0 {
		t.Fatalf("logged %s for a closed control channel", strings.Join(logged, "; "))
	}
}

func devNull(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// pipe returns a connected pair: theirs reads what ours writes.
func pipe(t *testing.T) (theirs, ours *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	return r, w
}

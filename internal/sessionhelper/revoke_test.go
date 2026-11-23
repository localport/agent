//go:build cgo && (linux || darwin)

package sessionhelper

import (
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/localport/agent/internal/launcher"
)

// controlPair is a control channel: the helper's end pollable, as Run makes
// it, so the watch's stop ends a pending read.
func controlPair(t *testing.T) (launcherEnd, helperEnd *os.File) {
	t.Helper()
	pollable, blocking, err := launcher.SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { blocking.Close() })
	return blocking, pollable
}

func manualTicks(ticks chan time.Time) func(time.Duration) (<-chan time.Time, func()) {
	return func(time.Duration) (<-chan time.Time, func()) { return ticks, func() {} }
}

func reasonWithin(t *testing.T, w *revocationWatch) string {
	t.Helper()
	select {
	case r := <-w.C():
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("no end reason")
		return ""
	}
}

// The launcher's End ends the session with its reason.
func TestRevocationWatchEndsOnTheLaunchersEnd(t *testing.T) {
	l, h := controlPair(t)
	w := watchRevocation(h, func() string { return launcher.FullDiskAccessGranted }, manualTicks(make(chan time.Time)), t.Logf)
	defer w.stop()
	if err := launcher.WriteHelperEnd(l, launcher.EndFullDiskAccessRevoked); err != nil {
		t.Fatal(err)
	}
	if r := reasonWithin(t, w); r != launcher.EndFullDiskAccessRevoked {
		t.Fatalf("reason %q", r)
	}
}

// With no launcher (it exited and closed its end), the helper's own reading
// ends the session at the first denied tick; granted and unknown end nothing.
func TestRevocationWatchSelfCheckWithoutALauncher(t *testing.T) {
	l, h := controlPair(t)
	l.Close()
	var reading atomic.Value
	reading.Store(launcher.FullDiskAccessGranted)
	reads := make(chan string, 1)
	ticks := make(chan time.Time)
	w := watchRevocation(h, func() string { v := reading.Load().(string); reads <- v; return v }, manualTicks(ticks), t.Logf)
	defer w.stop()
	// A tick is handled once the next one is taken: the ticks are unbuffered.
	tick := func(want string) {
		t.Helper()
		select {
		case ticks <- time.Now():
		case <-time.After(5 * time.Second):
			t.Fatal("the watch took no tick")
		}
		if got := <-reads; got != want {
			t.Fatalf("watch read %q, want %q", got, want)
		}
	}
	tick(launcher.FullDiskAccessGranted)
	reading.Store(launcher.FullDiskAccessUnknown)
	tick(launcher.FullDiskAccessUnknown)
	tick(launcher.FullDiskAccessUnknown)
	select {
	case r := <-w.C():
		t.Fatalf("ended %q on a granted or unknown reading", r)
	default:
	}
	reading.Store(launcher.FullDiskAccessDenied)
	tick(launcher.FullDiskAccessDenied)
	if r := reasonWithin(t, w); r != launcher.EndFullDiskAccessRevoked {
		t.Fatalf("reason %q", r)
	}
}

// After the session ended (stop), an End and a denied reading change nothing,
// and stop joins the watch's goroutines.
func TestRevocationWatchIgnoresAnEndAfterTheSession(t *testing.T) {
	l, h := controlPair(t)
	w := watchRevocation(h, func() string { return launcher.FullDiskAccessDenied }, manualTicks(make(chan time.Time)), t.Logf)
	w.stop()
	_ = launcher.WriteHelperEnd(l, launcher.EndFullDiskAccessRevoked)
	select {
	case r := <-w.C():
		t.Fatalf("ended %q after the session", r)
	case <-time.After(100 * time.Millisecond):
	}
}

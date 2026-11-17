//go:build linux || darwin

package session

import (
	"slices"
	"testing"
	"time"
)

// waitArmed waits until an idle timer is armed for which ok holds and returns
// its duration.
func (c *idleClock) waitArmed(t *testing.T, ok func(time.Duration) bool, why string) time.Duration {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.mu.Lock()
		i := slices.IndexFunc(c.idleArmed, ok)
		var d time.Duration
		if i >= 0 {
			d = c.idleArmed[i]
		}
		armed := slices.Clone(c.idleArmed)
		c.mu.Unlock()
		if i >= 0 {
			return d
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: idle timers armed %v", why, armed)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// connEnds records the reason of every connection end the server decides.
func connEnds(t *testing.T) <-chan string {
	t.Helper()
	ends := make(chan string, 4)
	hook := func(reason string) { ends <- reason }
	onConnEnd.Store(&hook)
	t.Cleanup(func() { onConnEnd.Store(nil) })
	return ends
}

func noEnd(t *testing.T, ends <-chan string) {
	t.Helper()
	select {
	case reason := <-ends:
		t.Fatalf("the connection ended with %q", reason)
	case <-time.After(100 * time.Millisecond):
	}
}

func wantEnd(t *testing.T, ends <-chan string, want string) {
	t.Helper()
	select {
	case reason := <-ends:
		if reason != want {
			t.Fatalf("the connection ended with %q, want %q", reason, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("the connection did not end, want %q", want)
	}
}

// The idle timer runs for the certificate's idle@localport.io value: a
// connection idle past it ends with CloseIdle, one idle for less keeps running
// and the timer is re-armed for the time left.
func TestIdleEndsAtTheCertificateTimeout(t *testing.T) {
	t.Run("idle past the certificate's timeout", func(t *testing.T) {
		clock := &idleClock{}
		f := newSSHFixture(t, func(c *ServerConfig) { c.clock = clock })
		ends := connEnds(t)
		o := f.defaults()
		o.idle = new("600")
		f.connect(t, o)
		clock.waitArmed(t, func(d time.Duration) bool { return d == 10*time.Minute }, "no idle timer for the certificate's 10 minutes")
		clock.advance(10*time.Minute + time.Second)
		clock.fireIdle()
		wantEnd(t, ends, CloseIdle)
	})
	t.Run("idle for less than the certificate's timeout", func(t *testing.T) {
		clock := &idleClock{}
		f := newSSHFixture(t, func(c *ServerConfig) { c.clock = clock })
		ends := connEnds(t)
		f.connect(t, f.defaults())
		clock.waitArmed(t, func(d time.Duration) bool { return d == testIdleTimeout }, "no idle timer for the certificate's 30 minutes")
		clock.advance(10*time.Minute + time.Second)
		clock.fireIdle()
		clock.waitArmed(t, func(d time.Duration) bool { return d < 20*time.Minute && d > 19*time.Minute },
			"the timer was not re-armed for the 20 minutes left")
		noEnd(t, ends)
	})
}

// A resume runs the connection under the resume certificate's idle timeout at
// once: the timer is re-armed for the new value, and idle past it ends the
// connection.
func TestResumeAppliesTheNewIdleTimeout(t *testing.T) {
	clock := &idleClock{}
	f := newSSHFixture(t, func(c *ServerConfig) { c.clock = clock })
	ends := connEnds(t)
	rc := f.connectResumable(t)
	clock.waitArmed(t, func(d time.Duration) bool { return d == testIdleTimeout }, "no idle timer for the first certificate's 30 minutes")
	rc.cut(t)
	if err := rc.resume(t, func(o *certOpts) { o.idle = new("600") }); err != nil {
		t.Fatalf("resume: %v", err)
	}
	clock.waitArmed(t, func(d time.Duration) bool { return d <= 10*time.Minute },
		"the resume did not re-arm the idle timer for its 10 minutes")
	clock.advance(10*time.Minute + time.Second)
	clock.fireIdle()
	wantEnd(t, ends, CloseIdle)
}

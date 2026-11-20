//go:build cgo && (linux || darwin)

package sessionhelper

import (
	"os"
	"sync"
	"time"

	"github.com/localport/agent/internal/launcher"
)

// revocationWatch ends a session started with Full Disk Access granted when
// the grant goes: on the launcher's HelperEnd, or on the helper's own reading
// every launcher.RevocationInterval, which covers a session whose launcher
// restarted (the helper outlives it and no new launcher adopts it). C yields
// the end reason at most once.
type revocationWatch struct {
	c       chan string
	once    sync.Once
	done    chan struct{}
	control *os.File
	wg      sync.WaitGroup
}

// watchRevocation starts the watch on control, the helper's end of the
// launcher control channel, which it then owns. read is the Full Disk Access
// reading; ticker returns the interval's ticks and their stop.
func watchRevocation(control *os.File, read func() string, ticker func(time.Duration) (<-chan time.Time, func())) *revocationWatch {
	w := &revocationWatch{c: make(chan string, 1), done: make(chan struct{}), control: control}
	w.wg.Go(func() {
		// An error is the launcher's exit or a message it never sends; the
		// self-check below stays in charge.
		if reason, err := launcher.ReadHelperEnd(control); err == nil {
			w.fire(reason)
		}
	})
	w.wg.Go(func() {
		ticks, stop := ticker(launcher.RevocationInterval)
		defer stop()
		for {
			select {
			case <-w.done:
				return
			case <-ticks:
				if read() != launcher.FullDiskAccessGranted {
					w.fire(launcher.EndFullDiskAccessRevoked)
					return
				}
			}
		}
	})
	return w
}

func (w *revocationWatch) fire(reason string) {
	w.once.Do(func() { w.c <- reason })
}

// C yields the reason the session must end for.
func (w *revocationWatch) C() <-chan string { return w.c }

// stop ends the watch once the session ended, for any reason: a later
// HelperEnd or reading changes nothing. It closes control, which ends the
// pending read, and joins both goroutines.
func (w *revocationWatch) stop() {
	w.once.Do(func() {})
	close(w.done)
	_ = w.control.Close()
	w.wg.Wait()
}

func realTicker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

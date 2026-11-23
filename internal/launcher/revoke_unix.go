//go:build linux || darwin

package launcher

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"
)

// RevocationInterval is how often a running session started with Full Disk
// Access granted re-reads it: the launcher while it serves such a session, and
// each such helper for its own session (a helper outlives a launcher restart).
const RevocationInterval = 30 * time.Second

// grantedSession is one running session whose helper started with Full Disk
// Access granted: Localport.app is responsible for what it touches.
type grantedSession struct {
	// control is the launcher's end of the helper's control channel; the run
	// goroutine that owns it closes it after removing the entry.
	control *os.File
	endOnce sync.Once
}

// end tells the helper once to end its session for the revoked grant. A
// helper whose session already ended ignores it. os.ErrClosed (the run
// goroutine closed the channel first) is not logged.
func (g *grantedSession) end(log func(string, ...any)) {
	g.endOnce.Do(func() {
		_ = g.control.SetWriteDeadline(time.Now().Add(replyTimeout))
		if err := WriteHelperEnd(g.control, EndFullDiskAccessRevoked); err != nil && !errors.Is(err, os.ErrClosed) {
			log("launcher: end a session for the revoked Full Disk Access: %v", err)
		}
	})
}

// revocation ends every granted session when Full Disk Access goes away.
// Its watcher runs only while a granted session runs and Serve is open (open
// to close). The set is memory only; helpers run their own check, which also
// covers sessions a closed or restarted launcher does not watch.
type revocation struct {
	read func() string
	// ticker returns the interval's ticks and their stop; end ends every
	// registered session. Tests replace both.
	ticker func(time.Duration) (<-chan time.Time, func())
	end    func()
	log    func(string, ...any)

	mu       sync.Mutex
	sessions map[*grantedSession]struct{}
	// stop is non-nil while a watcher may run; closing it stops the watcher.
	stop   chan struct{}
	closed bool
	// watchers: Add runs under mu and never while closed, so close's Wait
	// cannot race a new watcher.
	watchers sync.WaitGroup
}

func newRevocation(read func() string, log func(string, ...any)) *revocation {
	r := &revocation{read: read, log: log, ticker: realTicker, sessions: map[*grantedSession]struct{}{}}
	r.end = r.endAll
	return r
}

func realTicker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// open allows watchers under ctx and starts one for sessions still registered.
func (r *revocation) open(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = false
	if len(r.sessions) > 0 {
		r.startWatcherLocked(ctx)
	}
}

// add registers g and starts the watcher if none runs.
func (r *revocation) add(ctx context.Context, g *grantedSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[g] = struct{}{}
	r.startWatcherLocked(ctx)
}

// startWatcherLocked starts a watcher unless one runs or r is closed. Holds r.mu.
func (r *revocation) startWatcherLocked(ctx context.Context) {
	if r.stop == nil && !r.closed {
		r.stop = make(chan struct{})
		r.watchers.Add(1)
		go r.watch(ctx, r.stop)
	}
}

// remove drops g and stops the watcher when no granted session is left.
func (r *revocation) remove(g *grantedSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, g)
	if len(r.sessions) == 0 {
		r.stopWatcherLocked()
	}
}

// close stops the watcher and blocks new ones; it returns once none runs.
func (r *revocation) close() {
	r.mu.Lock()
	r.closed = true
	r.stopWatcherLocked()
	r.mu.Unlock()
	r.watchers.Wait()
}

// stopWatcherLocked closes stop if set. Holds r.mu.
func (r *revocation) stopWatcherLocked() {
	if r.stop != nil {
		close(r.stop)
		r.stop = nil
	}
}

// watch re-reads Full Disk Access each interval until stop closes or ctx
// ends, and ends every registered session at a denied reading. An unknown
// reading is logged once and read again at the next tick.
func (r *revocation) watch(ctx context.Context, stop <-chan struct{}) {
	defer r.watchers.Done()
	ticks, stopTicks := r.ticker(RevocationInterval)
	defer stopTicks()
	loggedUnknown := false
	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-ticks:
			switch r.read() {
			case FullDiskAccessDenied:
				r.end()
			case FullDiskAccessUnknown:
				if !loggedUnknown {
					loggedUnknown = true
					r.log("launcher: Full Disk Access unreadable; granted sessions keep running")
				}
			}
		}
	}
}

// endAll tells every registered session's helper to end. The writes run
// outside the lock: each is bounded by replyTimeout.
func (r *revocation) endAll() {
	r.mu.Lock()
	all := make([]*grantedSession, 0, len(r.sessions))
	for g := range r.sessions {
		all = append(all, g)
	}
	r.mu.Unlock()
	for _, g := range all {
		g.end(r.log)
	}
}

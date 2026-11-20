//go:build linux || darwin

package launcher

import (
	"context"
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
// helper whose session already ended ignores it, and a closed channel fails
// the write, which is harmless.
func (g *grantedSession) end(log func(string, ...any)) {
	g.endOnce.Do(func() {
		_ = g.control.SetWriteDeadline(time.Now().Add(replyTimeout))
		if err := WriteHelperEnd(g.control, EndFullDiskAccessRevoked); err != nil {
			log("launcher: end a session for the revoked Full Disk Access: %v", err)
		}
	})
}

// revocation ends every granted session when Full Disk Access goes away.
// Its watcher runs only while a granted session runs: add starts it, the
// remove that empties the set stops it. The set is memory only; a restarted
// launcher does not adopt running helpers, whose own check covers them.
type revocation struct {
	read func() string
	// ticker returns the interval's ticks and their stop; tests replace it.
	ticker func(time.Duration) (<-chan time.Time, func())
	log    func(string, ...any)

	mu       sync.Mutex
	sessions map[*grantedSession]struct{}
	// stop is non-nil while a watcher runs and closes to stop it.
	stop chan struct{}
	// watchers counts running watcher goroutines.
	watchers sync.WaitGroup
}

func newRevocation(read func() string, log func(string, ...any)) *revocation {
	return &revocation{read: read, log: log, ticker: realTicker, sessions: map[*grantedSession]struct{}{}}
}

func realTicker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// add registers g and starts the watcher if none runs.
func (r *revocation) add(ctx context.Context, g *grantedSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[g] = struct{}{}
	if r.stop == nil {
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
	if len(r.sessions) == 0 && r.stop != nil {
		close(r.stop)
		r.stop = nil
	}
}

// watch re-reads Full Disk Access each interval until stop closes or ctx
// ends, and ends every registered session at a reading that is not granted.
func (r *revocation) watch(ctx context.Context, stop <-chan struct{}) {
	defer r.watchers.Done()
	ticks, stopTicks := r.ticker(RevocationInterval)
	defer stopTicks()
	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-ticks:
			if r.read() != FullDiskAccessGranted {
				r.endAll()
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

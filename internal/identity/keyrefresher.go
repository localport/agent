package identity

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	// keyRefreshInterval is the scheduled refetch, so a long-connected agent
	// learns a rotated or revoked kid without re-registering or renewing.
	keyRefreshInterval = 6 * time.Hour

	// keyRefreshFloor is the least time between two fetch starts that
	// RefreshNow allows. Tickets naming an unknown kid call RefreshNow, so the
	// floor bounds what a stream of them costs the control plane.
	keyRefreshFloor = 5 * time.Minute

	// A failed fetch retries after minKeyRetry, doubling to maxKeyRetry.
	minKeyRetry = time.Minute
	maxKeyRetry = 30 * time.Minute
)

// ErrKeyRefresherStopped means RefreshNow was called while Run is not running,
// before it starts or after it returns.
var ErrKeyRefresherStopped = errors.New("ticket key refresher is not running")

// KeyRefresher keeps one device identity's ticket key set current from
// POST /v1/devices/keys. Run fetches at once when the stored set is empty,
// then every keyRefreshInterval with ±10 % jitter; RefreshNow fetches on
// demand, and Hint brings the next fetch forward to the earliest time
// keyRefreshFloor allows. Each fetch loads the identity's current credential, so a promoted
// certificate signs, and stores the result through TicketKeys.Replace. A failed
// fetch keeps the stored set and retries with exponential backoff from
// minKeyRetry to maxKeyRetry, each wait ±20 % jitter; any successful fetch
// resets the backoff.
//
// Fetches run one at a time, on a goroutine Run owns and joins, with their
// request bound to Run's context. OnEvent is never called with mu held.
type KeyRefresher struct {
	Store *Store
	Ref   Ref
	// OnEvent receives one line per notable transition. Optional.
	OnEvent func(string)

	// client replaces NewClient(APIURL). Tests set it to reach an httptest
	// server.
	client *Client
	// clock replaces the wall clock and its timers. Tests set it.
	clock keyClock
	// decided, when set, runs in RefreshNow after it has chosen to share,
	// start or skip a fetch and before it waits. Tests hold callers there.
	decided func()

	// changed wakes Run when a fetch ends, so it re-arms its timer for the
	// next fetch. Buffered by one: a pending wake already covers a later one.
	changed chan struct{}
	// fetches counts fetch goroutines; Run waits for them before returning.
	fetches sync.WaitGroup

	// mu guards the fields below and every decision on them.
	mu          sync.Mutex
	running     bool
	runCtx      context.Context
	inflight    *keyFetch
	lastAttempt time.Time // start of the latest fetch
	lastErr     error     // result of the latest finished fetch
	backoff     time.Duration
	nextDue     time.Time
	// hinted is set by Hint and cleared when a fetch starts: a fetch in flight
	// started before the hint, so its end keeps the next fetch at the floor.
	hinted bool
}

// keyFetch is one fetch that RefreshNow callers share. err is written before
// done closes and read only after.
type keyFetch struct {
	done chan struct{}
	err  error
}

// keyClock is the time source of a KeyRefresher. NewTimer returns the timer's
// channel and a stop function.
type keyClock interface {
	Now() time.Time
	NewTimer(d time.Duration) (<-chan time.Time, func() bool)
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

func (wallClock) NewTimer(d time.Duration) (<-chan time.Time, func() bool) {
	t := time.NewTimer(d)
	return t.C, t.Stop
}

func (r *KeyRefresher) now() time.Time {
	if r.clock == nil {
		return wallClock{}.Now()
	}
	return r.clock.Now()
}

func (r *KeyRefresher) newTimer(d time.Duration) (<-chan time.Time, func() bool) {
	if r.clock == nil {
		return wallClock{}.NewTimer(d)
	}
	return r.clock.NewTimer(d)
}

func (r *KeyRefresher) log(format string, args ...any) {
	if r.OnEvent != nil {
		r.OnEvent(fmt.Sprintf(format, args...))
	}
}

// Run schedules fetches until ctx ends, then waits for an in-flight fetch to
// return and returns. Call it once per KeyRefresher, after TicketKeys.Load:
// Run fetches at once when the loaded set is empty. A file Load could not
// read counts as empty; the fetch's Replace reports the remedy, and the
// backoff paces the retries until the file is fixed.
func (r *KeyRefresher) Run(ctx context.Context) {
	keys, err := r.Store.TicketKeys(r.Ref)
	if err != nil {
		r.log("identity: cannot refresh ticket keys: %v", err)
		return
	}

	r.mu.Lock()
	r.changed = make(chan struct{}, 1)
	r.running = true
	r.runCtx = ctx
	r.nextDue = r.now()
	// A hint given before Run started asks for the first fetch at once.
	if !keys.empty() && !r.hinted {
		r.nextDue = r.nextDue.Add(refreshWait())
	}
	r.mu.Unlock()
	defer r.stop()

	for {
		// Drain before reading the state: a wake sent earlier describes a
		// change this read already sees.
		select {
		case <-r.changed:
		default:
		}
		r.mu.Lock()
		busy := r.inflight != nil
		wait := r.nextDue.Sub(r.now())
		if !busy && wait <= 0 {
			r.startLocked(ctx)
			busy = true
		}
		r.mu.Unlock()

		// While a fetch runs, its end decides the next due time.
		var fire <-chan time.Time
		stopTimer := func() bool { return false }
		if !busy {
			fire, stopTimer = r.newTimer(wait)
		}
		select {
		case <-ctx.Done():
			stopTimer()
			return
		case <-fire:
		case <-r.changed:
			stopTimer()
		}
	}
}

// stop refuses further fetches and joins the one in flight, whose request
// ends with Run's context.
func (r *KeyRefresher) stop() {
	r.mu.Lock()
	r.running = false
	r.mu.Unlock()
	r.fetches.Wait()
}

// RefreshNow fetches the key set and returns the fetch's result. Concurrent
// callers share one fetch. Within keyRefreshFloor of the latest fetch start it
// does not fetch and returns the latest finished fetch's result: nil if it
// stored a set, else its error. ctx bounds only this caller's wait; the fetch
// continues under Run's context and its result is stored either way. It
// returns ErrKeyRefresherStopped while Run is not running.
func (r *KeyRefresher) RefreshNow(ctx context.Context) error {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return ErrKeyRefresherStopped
	}
	f := r.inflight
	if f == nil && !r.lastAttempt.IsZero() && r.now().Sub(r.lastAttempt) < keyRefreshFloor {
		err := r.lastErr
		r.mu.Unlock()
		r.notifyDecided()
		return err
	}
	if f == nil {
		f = r.startLocked(r.runCtx)
	}
	r.mu.Unlock()
	r.notifyDecided()

	select {
	case <-f.done:
		return f.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Hint asks for a fetch soon, after TicketKeys.Hint put a held kid under a
// hint: the next fetch is due at the earliest time keyRefreshFloor allows,
// and a fetch already in flight is followed by one at that time. A hint given
// before Run starts makes Run fetch at once. It does not block.
func (r *KeyRefresher) Hint() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hinted = true
	if !r.running || r.inflight != nil {
		return
	}
	if due := r.floorDueLocked(); due.Before(r.nextDue) {
		r.nextDue = due
		select {
		case r.changed <- struct{}{}:
		default:
		}
	}
}

// floorDueLocked is the earliest time keyRefreshFloor allows the next fetch
// to start. The caller holds mu.
func (r *KeyRefresher) floorDueLocked() time.Time {
	now := r.now()
	if r.lastAttempt.IsZero() {
		return now
	}
	if floor := r.lastAttempt.Add(keyRefreshFloor); floor.After(now) {
		return floor
	}
	return now
}

func (r *KeyRefresher) notifyDecided() {
	if r.decided != nil {
		r.decided()
	}
}

// startLocked starts a fetch under ctx. The caller holds mu, has seen no fetch
// in flight and has checked that Run is running.
func (r *KeyRefresher) startLocked(ctx context.Context) *keyFetch {
	f := &keyFetch{done: make(chan struct{})}
	r.inflight = f
	r.hinted = false
	r.lastAttempt = r.now()
	r.fetches.Add(1)
	go func() {
		defer r.fetches.Done()
		err := r.fetch(ctx)
		r.mu.Lock()
		retryIn := r.finishLocked(err)
		r.inflight = nil
		f.err = err
		r.mu.Unlock()
		close(f.done)
		select {
		case r.changed <- struct{}{}:
		default:
		}
		// Emitted last, without mu and after waiters are released, so OnEvent
		// may call RefreshNow or wait for another caller's RefreshNow.
		if err != nil && ctx.Err() == nil {
			r.log("identity: ticket key fetch for %s failed, retrying in %s: %v", r.Ref, retryIn.Round(time.Second), err)
		}
	}()
	return f
}

// finishLocked records a fetch's result, sets the next due time and returns
// the wait until it. The caller holds mu.
func (r *KeyRefresher) finishLocked(err error) time.Duration {
	r.lastErr = err
	wait := refreshWait()
	if err != nil {
		if r.backoff == 0 {
			r.backoff = minKeyRetry
		} else {
			r.backoff = min(2*r.backoff, maxKeyRetry)
		}
		wait = backoffWait(r.backoff)
	} else {
		r.backoff = 0
	}
	r.nextDue = r.now().Add(wait)
	if due := r.floorDueLocked(); r.hinted && due.Before(r.nextDue) {
		r.nextDue = due
		wait = due.Sub(r.now())
	}
	return wait
}

// fetch fetches the set with the identity's current credential and stores it.
func (r *KeyRefresher) fetch(ctx context.Context) error {
	cur, err := r.Store.Load(r.Ref)
	if err != nil {
		return err
	}
	client := r.client
	if client == nil {
		if client, err = NewClient(cur.Meta.APIURL); err != nil {
			return err
		}
	}
	keys, err := r.Store.TicketKeys(r.Ref)
	if err != nil {
		return err
	}
	generation := keys.Generation()
	set, err := client.FetchDeviceKeys(ctx, cur)
	if err != nil {
		return err
	}
	if err := keys.Replace(ctx, generation, *set); err != nil {
		if errors.Is(err, ErrTicketKeysUnreadable) {
			return fmt.Errorf("%w; fix the mode of ticket_keys.json to owner-only, or remove it if it is malformed, owned by another user or not a regular file", err)
		}
		return err
	}
	return nil
}

// refreshWait is keyRefreshInterval with ±10 % jitter, so devices enrolled
// together do not refetch together.
func refreshWait() time.Duration {
	return keyRefreshInterval - keyRefreshInterval/10 + jitter(keyRefreshInterval/5)
}

// backoffWait is a backoff step d with ±20 % jitter. The spread grows with d,
// so devices that failed together in an outage do not retry together even at
// maxKeyRetry.
func backoffWait(d time.Duration) time.Duration {
	return d - d/5 + jitter(2*d/5)
}

// empty reports whether the in-memory set holds no verification key.
func (t *TicketKeys) empty() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.keys) == 0
}

package recording

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"
)

// Failed open queue bounds.
const (
	maxFailedOpens       = 64
	failedOpenLifetime   = 10 * time.Minute
	failedOpenMaxBackoff = 30 * time.Second
)

// FailedOpen reports that a recorded start did not produce a recording.
type FailedOpen struct {
	ID         string
	SessionID  string
	Identifier string
	// KeySHA256 is the recording key hash the admitting certificate names.
	KeySHA256   []byte
	Certificate []byte
	// Reason is ReasonSpoolFull, ReasonDiskLow or ReasonRecordingFailed.
	Reason string
	// Channels is the stream's cumulative recorded start count, 0 for none.
	Channels int32
}

// failedOpen is one queued report, guarded by Uploader.mu.
type failedOpen struct {
	FailedOpen
	queuedAt time.Time
	next     time.Time
	attempt  int
	busy     bool
}

// ReportFailedOpen queues f and does not block, so a failed start never
// waits on the report. The queue is in memory, keeps at most maxFailedOpens
// entries and drops the oldest when full.
func (u *Uploader) ReportFailedOpen(f FailedOpen) {
	u.mu.Lock()
	if u.stopped {
		u.mu.Unlock()
		u.logFailedOpenDropped(f, "uploader stopped")
		return
	}
	var evicted *failedOpen
	if len(u.failed) >= maxFailedOpens {
		evicted = u.failed[0]
		u.failed = slices.Delete(u.failed, 0, 1)
	}
	u.failed = append(u.failed, &failedOpen{FailedOpen: f, queuedAt: u.now()})
	u.mu.Unlock()
	if evicted != nil {
		u.logFailedOpenDropped(evicted.FailedOpen, "queue full")
	}
	u.poke()
}

func (u *Uploader) logFailedOpenDropped(f FailedOpen, why string) {
	u.log.Warn("recording start failure not reported",
		slog.String("recording", f.ID), slog.String("reason", f.Reason), slog.String("why", why))
}

// dispatchFailedOpensLocked drops expired reports and starts each due one on
// a device with no control request running.
func (u *Uploader) dispatchFailedOpensLocked(ctx context.Context, now time.Time, later func(time.Time), results chan<- result, wg *sync.WaitGroup) {
	kept := u.failed[:0]
	for _, f := range u.failed {
		expiry := f.queuedAt.Add(failedOpenLifetime)
		switch {
		case f.busy:
		case !now.Before(expiry):
			u.logFailedOpenDropped(f.FailedOpen, "too old")
			continue
		case !u.configured(f.Identifier):
			u.logFailedOpenDropped(f.FailedOpen, "device no longer configured")
			continue
		case f.next.After(now):
			later(f.next)
			later(expiry)
		case u.control[f.Identifier] != 0 || u.strict[f.Identifier] != 0:
			later(expiry)
		default:
			u.control[f.Identifier]++
			f.busy = true
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, err := u.sendFailedOpen(ctx, f.FailedOpen)
				results <- result{failed: f, res: res, err: err}
			}()
		}
		kept = append(kept, f)
	}
	clear(u.failed[len(kept):])
	u.failed = kept
}

func (u *Uploader) sendFailedOpen(ctx context.Context, f FailedOpen) (Result, error) {
	c, err := u.client(f.Identifier)
	if err != nil {
		return Result{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, u.requestTimeout(0))
	defer cancel()
	return c.OpenFailed(ctx, f)
}

// applyFailedOpenLocked removes an answered report, drops a refused one and
// backs off the rest: no mux, a transport failure, busy or unavailable.
func (u *Uploader) applyFailedOpenLocked(r result) {
	f := r.failed
	f.busy = false
	if u.control[f.Identifier]--; u.control[f.Identifier] == 0 {
		delete(u.control, f.Identifier)
	}
	i := slices.Index(u.failed, f)
	if i < 0 {
		return
	}
	var ref *Refusal
	refused := errors.As(r.err, &ref)
	if r.err == nil || (refused && ref.Code != CodeBusy && ref.Code != CodeUnavailable) {
		if r.err != nil {
			u.logFailedOpenDropped(f.FailedOpen, ref.Code)
		}
		u.failed = slices.Delete(u.failed, i, i+1)
		return
	}
	// Full jitter, as backoffLocked: reports queued together do not retry in
	// step.
	limit := min(minBackoff<<min(f.attempt, 5), failedOpenMaxBackoff)
	wait := minBackoff + u.jitter(limit-minBackoff+1)
	f.attempt++
	if refused {
		wait = max(wait, ref.RetryAfter)
	}
	f.next = u.now().Add(wait)
}

// resetFailedOpensLocked makes the device's reports due at once.
func (u *Uploader) resetFailedOpensLocked(identifier string) {
	for _, f := range u.failed {
		if f.Identifier == identifier {
			f.attempt, f.next = 0, time.Time{}
		}
	}
}

func (u *Uploader) dropFailedOpensLocked() {
	for _, f := range u.failed {
		u.logFailedOpenDropped(f.FailedOpen, "uploader stopped")
	}
	u.failed = nil
}

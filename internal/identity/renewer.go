package identity

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// maxSleep caps one sleep, so a machine that suspends for a week, or whose
	// credential another process renewed, re-evaluates on a bounded schedule.
	maxSleep = 6 * time.Hour

	// The last third of a certificate's life is the retry budget: the server puts
	// renew_after two thirds through, so a failure backs off in minutes.
	minRetry = time.Minute
	maxRetry = time.Hour

	// minInterval floors the gap between two renewal ATTEMPTS, successful or not.
	// The loop otherwise sleeps only while renew_after is in the future, so a
	// certificate issued already past it would renew with no pause at all.
	minInterval = time.Minute
)

// Renewer keeps one credential fresh, driven by the renew_after the control
// plane sets, so cadence changes without shipping a new agent.
type Renewer struct {
	Store *Store
	Ref   Ref
	// OnEvent receives one line per notable transition. Optional.
	OnEvent func(string)
}

// lock takes the credential's renewal lock without blocking. It lives beside
// the material, so it is scoped to one credential, and the OS releases it if
// the holder dies.
func (r *Renewer) lock() (release func(), held bool, err error) {
	dir := r.Store.Dir(r.Ref)
	f, err := os.OpenFile(filepath.Join(dir, lockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, false, fmt.Errorf("open renewal lock: %w", err)
	}
	held, err = tryLockFile(f)
	if err != nil || !held {
		f.Close()
		return nil, false, err
	}
	return func() {
		_ = unlockFile(f)
		f.Close()
	}, true, nil
}

func (r *Renewer) log(format string, args ...any) {
	if r.OnEvent != nil {
		r.OnEvent(fmt.Sprintf(format, args...))
	}
}

// ErrRenewalInProgress means another process holds this credential's renewal
// lock. The caller waits rather than renewing alongside it.
var ErrRenewalInProgress = errors.New("another process is renewing this credential")

// RenewOnce renews unconditionally and stores the result.
//
// One renewal at a time per credential, across processes: a `localport access`
// and a cron `localport identity renew` are both legitimate writers, and
// renewing minutes apart orphans a certificate against the live cap. The
// in-process guard cannot see another process.
func (r *Renewer) RenewOnce(ctx context.Context) (*Material, error) {
	release, held, err := r.lock()
	if err != nil {
		return nil, err
	}
	if !held {
		return nil, ErrRenewalInProgress
	}
	defer release()

	cur, err := r.Store.Load(r.Ref)
	if err != nil {
		return nil, err
	}
	client, err := NewClient(cur.Meta.APIURL)
	if err != nil {
		return nil, err
	}
	next, err := client.Renew(ctx, cur)
	if err != nil {
		return nil, err
	}
	if _, err := r.Store.Save(*next); err != nil {
		return nil, err
	}
	return next, nil
}

// Run renews in the background until ctx ends. Every cycle re-reads the file:
// another process may have renewed, and signing from a stale certificate offers
// a serial the server has already superseded.
func (r *Renewer) Run(ctx context.Context) {
	backoff := minRetry
	var lastAttempt time.Time
	for {
		cur, err := r.Store.Load(r.Ref)
		if err != nil {
			r.log("identity: cannot read credential: %v", err)
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = nextRetry(backoff)
			continue
		}

		// Callers only start this loop for a renewable source, so an absent
		// deadline is a record disagreeing with itself. Stop rather than renew on
		// a missing field.
		due, ok := cur.Meta.NextRenewal()
		if !ok {
			return
		}
		if wait := time.Until(due); wait > 0 {
			if !sleepCtx(ctx, min(wait, maxSleep)) {
				return
			}
			continue
		}

		// Between ATTEMPTS, not before the first: a certificate issued already
		// past its renew_after would otherwise renew in a tight loop.
		if since := time.Since(lastAttempt); !lastAttempt.IsZero() && since < minInterval {
			if !sleepCtx(ctx, minInterval-since) {
				return
			}
			continue
		}
		lastAttempt = time.Now()

		next, err := r.RenewOnce(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// Not retryable, and the wait above never blocks, so retrying would
			// poll a refusing server flat out.
			if errors.Is(err, ErrNotRenewable) {
				r.log("identity: %v", err)
				return
			}
			// Another writer is producing the certificate this cycle wanted.
			// Queueing behind it is the burst the lock exists to prevent.
			if errors.Is(err, ErrRenewalInProgress) {
				if !sleepCtx(ctx, minInterval) {
					return
				}
				continue
			}
			// Still valid: renew_after is two thirds through the life, not the
			// expiry. A failure is a retry, not a reason to stop presenting it.
			r.log("identity: renewal failed, retrying in %s: %v", backoff.Round(time.Second), err)
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = nextRetry(backoff)
			continue
		}
		backoff = minRetry
		r.log("identity: renewed %s, valid until %s", next.Meta.Identity, next.Meta.NotAfter.Format(time.RFC3339))
	}
}

func nextRetry(d time.Duration) time.Duration {
	if d *= 2; d > maxRetry {
		return maxRetry
	}
	return d
}

// sleepCtx reports whether the sleep completed rather than being cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

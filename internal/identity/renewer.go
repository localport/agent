package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/localport/agent/internal/errcode"
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

	// client replaces NewClient(APIURL) in RenewPending. Tests set it to reach
	// an httptest server.
	client *Client
}

// lock takes the credential's renewal lock without blocking.
func (r *Renewer) lock() (release func(), held bool, err error) {
	return r.Store.tryLock(r.Ref)
}

func (r *Renewer) log(format string, args ...any) {
	if r.OnEvent != nil {
		r.OnEvent(fmt.Sprintf(format, args...))
	}
}

// ErrRenewalInProgress means another writer, in this or another process, holds
// this credential's renewal lock. The caller waits rather than renewing
// alongside it.
var ErrRenewalInProgress = errcode.New(errcode.RenewalInProgress)

// RenewOnce renews unconditionally and stores the result. A device credential
// is renewed from its current certificate and stored as pending, replacing any
// earlier pending one; Store.Promote makes it current.
//
// One renewal at a time per credential, in and across processes, through the
// credential's file lock: a `localport access` and a cron `localport identity
// renew` are both legitimate writers, and renewing minutes apart orphans a
// certificate against the live cap.
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
	return r.renewLocked(ctx, client, cur)
}

// renewLocked renews cur through client and stores the result. The caller
// holds the renewal lock.
func (r *Renewer) renewLocked(ctx context.Context, client *Client, cur *Material) (*Material, error) {
	generation := r.keyGeneration()
	next, err := client.Renew(ctx, cur)
	if err != nil {
		return nil, err
	}
	if cur.Meta.Kind != KindDevice {
		if _, err := r.Store.saveLocked(*next); err != nil {
			return nil, err
		}
		return next, nil
	}
	ref, err := r.Store.savePending(*next, cur.Meta.Serial)
	if err != nil {
		return nil, err
	}
	r.storeTicketKeys(ctx, ref, generation, next)
	return next, nil
}

// keyGeneration is the hint generation of the identity's ticket keys, read
// before a renewal request so the renewed set settles only earlier hints. It
// is 0 for an identity that holds no ticket keys.
func (r *Renewer) keyGeneration() uint64 {
	keys, err := r.Store.TicketKeys(r.Ref)
	if err != nil {
		return 0
	}
	return keys.Generation()
}

// storeTicketKeys stores a device renewal's key set in the identity's
// TicketKeys. The credential is already stored, so a failure is logged and
// the renewal still succeeds; the next renewal or key refresh stores the set
// once ticket_keys.json is readable. Only ErrTicketKeysUnreadable is logged
// with the file remedy. The caller holds the renewal lock, which may be held
// while taking the key lock.
func (r *Renewer) storeTicketKeys(ctx context.Context, ref Ref, generation uint64, next *Material) {
	if next.DeviceKeys == nil {
		return
	}
	keys, err := r.Store.TicketKeys(ref)
	if err == nil {
		err = keys.Replace(ctx, generation, *next.DeviceKeys)
	}
	switch {
	case errors.Is(err, ErrTicketKeysUnreadable):
		r.log("identity: renewed %s, but its ticket keys were not stored: %v; fix the mode of ticket_keys.json to owner-only, or remove it if it is malformed, owned by another user or not a regular file, and the next key fetch or renewal writes the set", ref, err)
	case err != nil:
		r.log("identity: renewed %s, but its ticket keys were not stored: %v", ref, err)
	}
}

// RenewPending renews a device's pending credential from its own key and
// stores the result as the new pending one. The device runs it when the edge
// refuses the pending certificate as neither current nor pending. It returns
// ErrNoPending when nothing is pending and ErrRenewalInProgress while another
// writer holds the lock.
func (r *Renewer) RenewPending(ctx context.Context) (*Material, error) {
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
	pending, err := r.Store.LoadPending(r.Ref)
	if err != nil {
		return nil, err
	}
	client := r.client
	if client == nil {
		if client, err = NewClient(pending.Meta.APIURL); err != nil {
			return nil, err
		}
	}
	generation := r.keyGeneration()
	next, err := client.Renew(ctx, pending)
	if err != nil {
		return nil, err
	}
	ref, err := r.Store.savePending(*next, cur.Meta.Serial)
	if err != nil {
		return nil, err
	}
	r.storeTicketKeys(ctx, ref, generation, next)
	r.log("identity: renewed %s from its pending certificate, valid until %s", next.Meta.Identity, next.Meta.NotAfter.Format(time.RFC3339))
	return next, nil
}

// due returns when the credential next renews and whether it renews at all.
// A pending device renewal governs once it exists: renewing again before it
// is promoted would only replace it. An expired certificate is due now, since
// the device route accepts it and waiting only extends the outage.
func (r *Renewer) due(cur Meta) (time.Time, bool, error) {
	effective := cur
	if cur.Kind == KindDevice {
		_, pending, err := r.Store.readPair(r.Ref)
		if err != nil {
			return time.Time{}, false, err
		}
		if pending != nil {
			effective = *pending
		}
	}
	due, ok := effective.NextRenewal()
	if !ok {
		return time.Time{}, false, nil
	}
	if now := time.Now(); !effective.NotAfter.After(now) {
		return now, true, nil
	}
	return due, true, nil
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
		due, ok, err := r.due(cur.Meta)
		if err != nil {
			r.log("identity: cannot read credential: %v", err)
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = nextRetry(backoff)
			continue
		}
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
			// A failure is retried and the certificate stays in use:
			// renew_after is two thirds through its life, and an expired device
			// certificate still renews at the device route. A Retry-After longer
			// than the backoff is waited out, up to maxRetry. Either wait is
			// jittered so devices behind one address do not return in step.
			base := backoff
			if asked, ok := serverRetryAfter(err); ok && asked > base {
				base = min(asked, maxRetry)
			}
			wait := withJitter(base)
			r.log("identity: renewal failed, retrying in %s: %v", wait.Round(time.Second), err)
			if !sleepCtx(ctx, wait) {
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

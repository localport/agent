package tunnel

import (
	"context"
	"math/rand/v2"
	"time"

	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/proto"
)

const (
	// refusalBackoffBase is the first wait of a device refused with a
	// retry_after hint; each refusal doubles it.
	refusalBackoffBase = 30 * time.Second
	// maxRefusalWait caps that wait and the hint (Tailscale's maxRetryWindow).
	maxRefusalWait = 5 * time.Minute
	// recordingDrainBound bounds the wait, on an admin's Disconnect, for the
	// device's recordings to reach the server before the connection closes.
	// Entries not delivered stay in the spool.
	recordingDrainBound = 60 * time.Second
)

// Status is a tunnel's state for the status endpoint: Code is the refusal a
// waiting tunnel retries after, NextRetry when it retries, Since when State
// was entered.
type Status struct {
	State     State
	Code      string
	Since     time.Time
	NextRetry time.Time
}

// kick is a Shutdown that carried a retry_after hint: the device closes the
// session, after a drain for SE040, and waits as for a hinted refusal.
type kick struct {
	code       string
	retryAfter time.Duration
	drain      bool
}

// refusalWait is the Full Jitter wait before the n-th consecutive retry of a
// hinted refusal: uniform in [0, min(maxRefusalWait, max(hint, backoff))),
// the backoff doubling from refusalBackoffBase.
func refusalWait(hint time.Duration, n int) time.Duration {
	backoff := refusalBackoffBase << min(max(n-1, 0), 4)
	upper := min(maxRefusalWait, max(hint, backoff))
	return rand.N(upper)
}

// waitRefused records the refusal with code in the tunnel's status and waits
// before the next registration. A network change does not end the wait: the
// control plane, not the link, decides when the refusal lifts. It returns
// false when the tunnel stops first.
func (t *Tunnel) waitRefused(ctx context.Context, code string, hint time.Duration, n int) bool {
	d := refusalWait(hint, n)
	t.setWaiting(code, t.now().Add(d))
	select {
	case <-ctx.Done():
		return false
	case <-t.shutdown:
		return false
	case <-t.after(d):
		return true
	}
}

// setWaiting enters StateWaiting with the refusal code and retry time.
func (t *Tunnel) setWaiting(code string, next time.Time) {
	t.statusMu.Lock()
	t.waitCode, t.nextRetry = code, next
	t.statusMu.Unlock()
	t.setState(StateWaiting)
	// setState notifies only on a change; a repeated wait changes the code
	// or the retry time.
	t.notifyStatus()
}

// Status returns the tunnel's current state for the status endpoint.
func (t *Tunnel) Status() Status {
	t.statusMu.Lock()
	defer t.statusMu.Unlock()
	st := Status{State: State(t.state.Load()), Since: t.stateSince}
	if st.State == StateWaiting {
		st.Code, st.NextRetry = t.waitCode, t.nextRetry
	}
	return st
}

// notifyStatus hands the current status to Options.OnStatus.
func (t *Tunnel) notifyStatus() {
	if t.opts.OnStatus != nil {
		t.opts.OnStatus(t.Status())
	}
}

// kickOf is the hinted Shutdown sd describes for a device, or nil when sd is
// nil, carries no hint, or the tunnel is not a device.
func (t *Tunnel) kickOf(sd *proto.ShutdownPayload) *kick {
	if sd == nil || !t.IsDevice() || sd.RetryAfter == 0 {
		return nil
	}
	return &kick{
		code:       sd.Code,
		retryAfter: time.Duration(sd.RetryAfter) * time.Second,
		drain:      sd.Code == identity.CodeDeviceDisabled,
	}
}

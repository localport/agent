package identity

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/localport/agent/internal/errcode"
)

// Edge refusal codes the registrar acts on. The edge forwards them in
// RegisterAck.error_code.
const (
	// codeCertExpired: the device certificate is outside its validity period.
	codeCertExpired = "SE006"
	// codeDeviceCertRefused: the certificate is not the device's current or
	// pending one, or the device is revoked or removed.
	codeDeviceCertRefused = "SE031"
)

// RolloverDeadline is how long before the current certificate expires the
// device switches to a pending one even while sessions are open.
const RolloverDeadline = 24 * time.Hour

// ErrPendingLost means the renewed certificate this process already
// registered with is gone from the store, and the certificate before it may be
// superseded. Enrolling the device again is the only way back.
var ErrPendingLost = errcode.New(errcode.PendingLost)

// DeviceRegistrar chooses the certificate a device registers with and applies
// the outcome of each registration, carrying a renewed certificate from
// pending to current:
//
//   - A registration presents the pending certificate whenever one exists, so
//     a restart after the control plane promoted it registers with it.
//   - Once a pending certificate was presented, the one before it is never
//     presented again: the control plane may already have superseded it.
//   - Store.Promote, which deletes the previous key, runs only after a
//     RegisterAck on the pending certificate, and is retried until it lands
//     or the store reports the pending certificate replaced or gone.
//   - Each presented serial has its own TLS session cache, so the first
//     handshake after the switch sends the new certificate rather than
//     resuming a session bound to the old one.
//
// It is safe for concurrent use.
type DeviceRegistrar struct {
	store   *Store
	ref     Ref
	onEvent func(string)
	// client, set by tests, replaces NewClient in the renewal Refused runs.
	client *Client

	mu sync.Mutex
	// attempted is the serial of the last pending certificate presented.
	attempted string
	// unpromoted is a serial the edge acknowledged that Promote has not made
	// current yet.
	unpromoted  string
	cacheSerial string
	cache       tls.ClientSessionCache
	// renewalRefused is the last definitive renewal refusal, cleared when a
	// renewal lands.
	renewalRefused error
	// registered is the certificate of the last acknowledged Presentation.
	registered *tls.Certificate
}

// Presentation is the certificate offered at one registration.
type Presentation struct {
	Certificate  *tls.Certificate
	Serial       string
	Pending      bool
	SessionCache tls.ClientSessionCache
}

// NewDeviceRegistrar returns the registrar of the device credential ref.
// onEvent, optional, receives one line per rollover transition.
func NewDeviceRegistrar(store *Store, ref Ref, onEvent func(string)) *DeviceRegistrar {
	return &DeviceRegistrar{store: store, ref: ref, onEvent: onEvent}
}

func (r *DeviceRegistrar) log(format string, args ...any) {
	if r.onEvent != nil {
		r.onEvent(fmt.Sprintf(format, args...))
	}
}

// Present returns the certificate for the next registration. A store read
// error is returned as is for the caller to retry; nothing is deleted.
//
// The pending credential is read before the current one. Promote writes
// meta.json, then removes pending.json, so a promotion running between the
// reads shows either as still pending or, once pending.json is gone, as the
// current credential the second read returns; reading in the other order
// could see the old current credential and no pending one.
func (r *DeviceRegistrar) Present() (*Presentation, error) {
	var chosen *Material
	pending := false
	switch next, err := r.store.LoadPending(r.ref); {
	case err == nil:
		chosen, pending = next, true
	case !errors.Is(err, ErrNoPending):
		return nil, err
	default:
		if chosen, err = r.store.Load(r.ref); err != nil {
			return nil, err
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	serial := chosen.Meta.Serial
	if !pending && r.attempted != "" && serial != r.attempted {
		return nil, ErrPendingLost
	}
	cert, err := chosen.TLSCertificate()
	if err != nil {
		return nil, fmt.Errorf("device credential %s: %w", r.ref, err)
	}
	if pending {
		r.attempted = serial
	}
	if r.cacheSerial != serial {
		r.cache = tls.NewLRUClientSessionCache(4)
		r.cacheSerial = serial
	}
	return &Presentation{Certificate: cert, Serial: serial, Pending: pending, SessionCache: r.cache}, nil
}

// Registered records that the edge accepted p: RegisteredCertificate returns
// p's certificate from then on. A pending certificate is promoted to current;
// when the store cannot promote it yet, Tick retries.
func (r *DeviceRegistrar) Registered(p *Presentation) {
	r.mu.Lock()
	r.registered = p.Certificate
	if !p.Pending {
		r.mu.Unlock()
		return
	}
	r.unpromoted = p.Serial
	r.mu.Unlock()
	r.promote()
}

// RegisteredCertificate returns the certificate, with its key, of the last
// acknowledged registration, and false before the first. It can differ from
// Store.Load between a RegisterAck on a renewed certificate and its promotion;
// the edge binds session tickets to this one.
func (r *DeviceRegistrar) RegisteredCertificate() (*tls.Certificate, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.registered, r.registered != nil
}

func (r *DeviceRegistrar) promote() {
	r.mu.Lock()
	serial := r.unpromoted
	r.mu.Unlock()
	if serial == "" {
		return
	}
	// A reconnect before the promotion landed acknowledges the same serial
	// again; Promote then only finishes cleanup and is not reported.
	already := false
	if cur, err := r.store.Load(r.ref); err == nil {
		already = cur.Meta.Serial == serial
	}
	err := r.store.Promote(r.ref, serial)
	done := err == nil || errors.Is(err, ErrPendingChanged) || errors.Is(err, ErrNoPending)
	switch {
	case err == nil && already:
	case err == nil:
		r.log("identity: %s now registers with its renewed certificate", r.ref)
	case errors.Is(err, ErrRenewalInProgress):
	case done:
		r.log("identity: %s: renewed certificate not promoted: %v", r.ref, err)
	default:
		r.log("identity: %s: promoting the renewed certificate failed, retrying: %v", r.ref, err)
	}
	if done {
		r.mu.Lock()
		if r.unpromoted == serial {
			r.unpromoted = ""
		}
		r.mu.Unlock()
	}
}

// Refused decides whether a registration refused with the edge code code is
// worth retrying, after acting on it:
//
//   - SE006 (expired) is retried: the renewer renews an expired device
//     certificate, and the next registration presents the result. Once the
//     renewer reported a definitive refusal (RenewalRefused) it stops.
//   - SE031 on a pending certificate renews again from the pending key, then
//     retries. A definitive renewal refusal stops.
//
// Anything else keeps the edge's verdict (retry is false).
func (r *DeviceRegistrar) Refused(ctx context.Context, p *Presentation, code string) (retry bool, err error) {
	switch {
	case code == codeCertExpired:
		r.mu.Lock()
		refused := r.renewalRefused
		r.mu.Unlock()
		if refused != nil {
			return false, refused
		}
		return true, nil
	case code == codeDeviceCertRefused && p.Pending:
		_, err := (&Renewer{Store: r.store, Ref: r.ref, OnEvent: r.onEvent, client: r.client}).RenewPending(ctx)
		if err != nil && definitiveRefusal(err) {
			return false, err
		}
		if err != nil {
			r.log("identity: %s: renewing the refused certificate failed, retrying: %v", r.ref, err)
		}
		return true, nil
	}
	return false, nil
}

// RenewalRefused records a definitive renewal refusal from the renewal loop,
// or clears it with nil after a renewal lands. Wire it to Renewer.OnRefused.
func (r *DeviceRegistrar) RenewalRefused(err error) {
	r.mu.Lock()
	r.renewalRefused = err
	r.mu.Unlock()
}

// definitiveRefusal reports a renewal the control plane refused for good: a
// 4xx other than 429, or a credential that does not renew.
func definitiveRefusal(err error) bool {
	if errors.Is(err, ErrNotRenewable) {
		return true
	}
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Status >= 400 && apiErr.Status < 500 &&
		apiErr.Status != http.StatusTooManyRequests
}

// Tick retries a promotion the store refused earlier and reports whether a
// session registered with p should end so the device registers with a pending
// certificate: due when the store holds a pending certificate other than the
// one p presented, forced once the current certificate is within
// RolloverDeadline of expiry. The decision is by serial, since a session that
// registered with a pending certificate keeps that presentation after the
// promotion. A store read error reports nothing due.
func (r *DeviceRegistrar) Tick(p *Presentation, now time.Time) (due, force bool) {
	r.promote()
	if p == nil {
		return false, false
	}
	cur, pending, err := r.store.readPair(r.ref)
	if err != nil || pending == nil || pending.Serial == p.Serial {
		return false, false
	}
	return true, !now.Before(cur.NotAfter.Add(-RolloverDeadline))
}

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/localport/agent/internal/agent"
	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/recording"
	"github.com/localport/agent/internal/session"
	"github.com/localport/agent/internal/status"
	"github.com/localport/agent/internal/tunnel"
)

// reloadSessionWait bounds how long a reload waits for the sessions of a
// changed device to end before it stops the device's tunnel.
const reloadSessionWait = 5 * time.Second

// servedDevice is one running device: its config entry, its session server
// (nil when sessions are off), its sessions lock, and its renewal and key
// refresh loops, which run under their own context so a reload can end them.
type servedDevice struct {
	local config.LocalDevice
	// paused marks an entry `localport down` paused, removed a device whose
	// credential was forgotten, parked a device refused for a reason only a
	// reload, `up` or a restart retries; code is the refusal behind removed or
	// parked, which may be empty. None of them runs a tunnel.
	paused    bool
	removed   bool
	parked    bool
	code      string
	sessions  *session.Server
	lock      *session.SessionsLock
	unshare   func() // the store lock hold lock needs; nil once released
	renewer   *identity.Renewer
	refresher *identity.KeyRefresher
	cancel    context.CancelFunc
	loops     sync.WaitGroup
}

// start runs the device's loops under a child of ctx.
func (s *servedDevice) start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	if s.renewer != nil {
		s.loops.Go(func() { s.renewer.Run(ctx) })
	}
	if s.refresher != nil {
		s.loops.Go(func() { s.refresher.Run(ctx) })
	}
}

// end stops the device's loops, waits for them and releases its sessions
// lock. The device's tunnel has stopped by then. A second call does nothing
// more.
func (s *servedDevice) end() {
	if s.cancel != nil {
		s.cancel()
	}
	s.loops.Wait()
	_ = s.lock.Close()
	if s.unshare != nil {
		s.unshare()
		s.unshare = nil
	}
}

// deviceRunner builds and tracks the served devices of one serveDevices call.
// served is used only by the goroutine that builds the devices and then by
// the reload loop.
type deviceRunner struct {
	parent   context.Context
	store    *identity.Store
	uploads  *recording.Uploader
	notices  *tunnel.ClipboardNotices
	logEvent func(string)
	probe    sessionProbe
	probed   bool
	// noMux keeps the launcher unprobed: no session runs.
	noMux  bool
	served map[identity.Ref]*servedDevice
	// configured is the device list the uploader accepts recordings for:
	// the config's, less the removed devices.
	configured atomic.Pointer[[]config.LocalDevice]
	// board receives each device's state for the status endpoint; nil
	// publishes none.
	board *status.Board

	// forget is store.Forget; tests replace it to observe the end order.
	forget func(ctx context.Context, ref identity.Ref, code, serial string) (bool, error)

	// ends queues device ends for the owner goroutine; endWake signals it.
	endsMu  sync.Mutex
	ends    []deviceEnd
	endWake chan struct{}
}

// deviceEnd is a device tunnel's end, or a removal refusal from its renewal
// or key refresh loop (tunnel nil).
type deviceEnd struct {
	identifier string
	tunnel     *tunnel.Tunnel
	err        error
}

// build makes the runtime spec of d and its served state. A device that
// cannot start is logged and skipped (ok false).
func (r *deviceRunner) build(d config.LocalDevice) (spec config.DeviceSpec, ok bool) {
	if d.Paused {
		r.served[d.Identity] = &servedDevice{local: d, paused: true}
		r.publish(d.Identity, status.StatePaused, "")
		fmt.Fprintf(os.Stderr, "  skipped: %s is paused; resume it %s\n", d.Identity, elevatedCommand("up"))
		return config.DeviceSpec{}, false
	}
	if code, removed := r.tombstoned(d.Identity); removed {
		r.served[d.Identity] = &servedDevice{local: d, removed: true, code: code}
		fmt.Fprintf(os.Stderr, "  skipped: %s was removed (%s); enrol it again %s\n", d.Identity, code, elevatedCommand("up <join-token>"))
		r.publish(d.Identity, status.StateRemoved, code)
		return config.DeviceSpec{}, false
	}
	if !r.probed && d.UsesLogins() {
		r.probe, r.probed = probeLauncher(r.parent, r.logEvent), true
	}
	spec, renews, err := deviceSpec(r.store, d, r.probe, r.logEvent)
	if err != nil {
		// err names the device.
		fmt.Fprintf(os.Stderr, "  skipped: %v\n", err)
		return config.DeviceSpec{}, false
	}
	served := &servedDevice{local: d}
	state, err := deviceSessions(r.store, d.Identity, &spec, r.uploads, r.notices, r.logEvent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  device %s: sessions disabled: %v\n", d.Identity, err)
	} else if state != nil {
		served.refresher, served.lock, served.unshare = state.refresher, state.lock, state.unshare
		served.sessions, _ = spec.SessionHandler.(*session.Server)
	}
	onRemoved := func(err *identity.RemovedError) {
		r.queueEnd(deviceEnd{identifier: d.Identity.Identity, err: err})
	}
	if renews {
		served.renewer = &identity.Renewer{
			Store: r.store, Ref: d.Identity, OnEvent: r.logEvent, OnRefused: spec.Credential.RenewalRefused,
			OnRemoved: onRemoved,
		}
	}
	if served.refresher != nil {
		served.refresher.OnRemoved = onRemoved
	}
	identifier := d.Identity.Identity
	spec.OnStatus = func(st tunnel.Status) { r.publishTunnel(identifier, st) }
	if r.uploads != nil {
		spec.FlushRecordings = func(ctx context.Context) { _ = r.uploads.Flush(ctx, identifier) }
	}
	r.served[d.Identity] = served
	r.publish(d.Identity, status.StateConnecting, "")
	return spec, true
}

// tombstoned reports a device whose credential was forgotten: it has a
// tombstone and no readable credential. A tombstone beside a credential is
// left from before a crash or a new enrolment; the credential is used, and a
// removal refusal forgets it again.
func (r *deviceRunner) tombstoned(ref identity.Ref) (code string, removed bool) {
	t, err := r.store.ReadTombstone(ref)
	if err != nil {
		r.logEvent(fmt.Sprintf("identity: %v", err))
		return "", false
	}
	if t == nil {
		return "", false
	}
	if _, err := r.store.Load(ref); err == nil {
		return "", false
	}
	return t.Code, true
}

// reload applies devices, a re-read local config: a device whose entry
// changed or is gone ends its sessions with close {config_changed}, stops its
// tunnel and loops; a changed or added device then starts. Unchanged devices
// and their sessions are left alone.
func (r *deviceRunner) reload(ctx context.Context, a *agent.Agent, devices []config.LocalDevice) {
	// The launcher is probed again on reload: Full Disk Access or the
	// launcher itself may have changed since the last probe.
	r.probed = r.noMux
	next := make(map[identity.Ref]config.LocalDevice, len(devices))
	for _, d := range devices {
		next[d.Identity] = d
	}
	var stop []*tunnel.Tunnel
	var ended []*servedDevice
	for ref, s := range r.served {
		// A parked device is retried; a removed one stays until its entry
		// changes or goes.
		if d, ok := next[ref]; ok && d.Equal(s.local) && !s.parked {
			continue
		}
		if s.sessions != nil {
			waitCtx, cancel := context.WithTimeout(ctx, reloadSessionWait)
			if err := s.sessions.ShutdownConfigChanged(waitCtx); err != nil {
				r.logEvent(fmt.Sprintf("reload: the sessions of %s did not end in time: %v", ref, err))
			}
			cancel()
		}
		if t := deviceTunnel(a.Tunnels(), ref.Identity); t != nil {
			stop = append(stop, t)
		}
		ended = append(ended, s)
		delete(r.served, ref)
		if _, ok := next[ref]; !ok && r.board != nil {
			r.board.Remove(ref.Identity)
		}
	}
	r.pruneTombstones(devices)
	var added []config.LocalDevice
	for _, d := range devices {
		if _, ok := r.served[d.Identity]; !ok {
			added = append(added, d)
		}
	}
	if len(stop) == 0 && len(ended) == 0 && len(added) == 0 {
		r.logEvent("reload: no device changed")
		return
	}
	r.storeConfigured(devices)
	_, err := a.Apply(stop, func() []config.DeviceSpec {
		for _, s := range ended {
			s.end()
		}
		specs := make([]config.DeviceSpec, 0, len(added))
		for _, d := range added {
			spec, ok := r.build(d)
			if !ok {
				continue
			}
			r.served[d.Identity].start(ctx)
			specs = append(specs, spec)
		}
		return specs
	})
	// build marked the removed devices; the uploader takes no recordings of them.
	r.storeConfigured(devices)
	if err != nil {
		r.logEvent(fmt.Sprintf("reload: %v", err))
		return
	}
	r.logEvent(fmt.Sprintf("reload: stopped %d device(s), started %d", len(ended), len(added)))
}

// storeConfigured sets the device list the uploader accepts recordings for:
// devices less those whose credential was forgotten.
func (r *deviceRunner) storeConfigured(devices []config.LocalDevice) {
	kept := make([]config.LocalDevice, 0, len(devices))
	for _, d := range devices {
		if s, ok := r.served[d.Identity]; !ok || !s.removed {
			kept = append(kept, d)
		}
	}
	r.configured.Store(&kept)
}

// pruneTombstones deletes the tombstones of devices no longer in devices: the
// root command that removed the entry has read them. The runner owns the
// store, so root never deletes them itself.
func (r *deviceRunner) pruneTombstones(devices []config.LocalDevice) {
	refs, err := r.store.Tombstones()
	if err != nil {
		r.logEvent(fmt.Sprintf("identity: %v", err))
		return
	}
	for _, ref := range refs {
		if slices.ContainsFunc(devices, func(d config.LocalDevice) bool { return d.Identity == ref }) {
			continue
		}
		if err := r.store.DeleteTombstone(ref); err != nil {
			r.logEvent(fmt.Sprintf("identity: %v", err))
		}
	}
}

// publish sets the board row of ref.
func (r *deviceRunner) publish(ref identity.Ref, state, code string) {
	if r.board != nil {
		r.board.Set(status.Device{Identity: ref.Identity, State: state, Code: code, Since: time.Now().UTC()})
	}
}

// publishTunnel sets the board row of a running device tunnel. A stopped
// tunnel publishes nothing: its end decides the row.
func (r *deviceRunner) publishTunnel(identifier string, st tunnel.Status) {
	if r.board == nil {
		return
	}
	row := status.Device{Identity: identifier, Since: st.Since.UTC()}
	switch st.State {
	case tunnel.StateActive:
		row.State = status.StateRunning
	case tunnel.StateDraining:
		row.State = status.StateDraining
	case tunnel.StateWaiting:
		row.State, row.Code = status.StateWaiting, st.Code
		if st.Code == identity.CodeDeviceDisabled {
			row.State = status.StateDisconnected
		}
		next := st.NextRetry.UTC()
		row.NextRetry = &next
	case tunnel.StateStopped:
		return
	default:
		row.State = status.StateConnecting
	}
	r.board.Set(row)
}

// queueEnd hands ev to the owner goroutine. It never blocks: it runs on
// tunnel, renewal and key refresh goroutines that handleEnd waits for.
func (r *deviceRunner) queueEnd(ev deviceEnd) {
	r.endsMu.Lock()
	r.ends = append(r.ends, ev)
	r.endsMu.Unlock()
	select {
	case r.endWake <- struct{}{}:
	default:
	}
}

// handleEnds runs handleEnd for every queued end. Owner goroutine only.
func (r *deviceRunner) handleEnds(ctx context.Context, a *agent.Agent) {
	r.endsMu.Lock()
	ends := r.ends
	r.ends = nil
	r.endsMu.Unlock()
	for _, ev := range ends {
		r.handleEnd(ctx, a, ev)
	}
}

// handleEnd ends a device refused for good: its tunnel is stopped and
// awaited, its loops cancelled and awaited and its sessions lock released,
// then a removal refusal (SE018, SE041) forgets the credential it names and
// any other refusal parks the device. An end of a tunnel a reload already
// replaced, or of a device already ended, does nothing.
func (r *deviceRunner) handleEnd(ctx context.Context, a *agent.Agent, ev deviceEnd) {
	ref, s := r.servedByIdentifier(ev.identifier)
	if s == nil || s.paused || s.removed || s.parked {
		return
	}
	current := deviceTunnel(a.Tunnels(), ev.identifier)
	if ev.tunnel != nil && current != ev.tunnel {
		return
	}
	code, serial, forget := endAction(ev.err)
	if current != nil {
		// Removes it from the agent and waits for it; after Run has returned
		// every tunnel has already ended.
		_, _ = a.Apply([]*tunnel.Tunnel{current}, nil)
	}
	s.end()
	if !forget {
		s.parked, s.code = true, code
		r.logEvent(fmt.Sprintf("device %s: stopped until a reload, `localport up` or a restart: %v", ref, ev.err))
		r.publish(ref, status.StateParked, code)
		return
	}
	forgotten, err := r.forget(context.WithoutCancel(ctx), ref, code, serial)
	switch {
	case err != nil:
		s.parked, s.code = true, code
		r.logEvent(fmt.Sprintf("device %s: removed (%s), but its credential was not deleted: %v", ref, code, err))
		r.publish(ref, status.StateParked, code)
	case !forgotten:
		// A new enrolment replaced the refused credential: run it.
		r.logEvent(fmt.Sprintf("device %s: the refused credential was replaced; starting the stored one", ref))
		delete(r.served, ref)
		_, _ = a.Apply(nil, func() []config.DeviceSpec {
			spec, ok := r.build(s.local)
			if !ok {
				return nil
			}
			r.served[ref].start(ctx)
			return []config.DeviceSpec{spec}
		})
	default:
		s.removed, s.code = true, code
		r.logEvent(fmt.Sprintf("device %s: refused with %s (removed or enrolled again); its credential and recordings are deleted. Enrol it again %s", ref, code, elevatedCommand("up <join-token>")))
		if devices := r.configured.Load(); devices != nil {
			r.storeConfigured(*devices)
		}
		if r.uploads != nil {
			r.uploads.Forget(ev.identifier)
		}
		r.publish(ref, status.StateRemoved, code)
	}
}

// endAction classifies a device end: a removal refusal forgets the credential
// with serial; anything else parks with the edge's code.
func endAction(err error) (code, serial string, forget bool) {
	if removed, ok := errors.AsType[*identity.RemovedError](err); ok {
		return removed.Code, removed.Serial, true
	}
	if regErr, ok := errors.AsType[*tunnel.RegistrationError](err); ok {
		return regErr.Code, regErr.Serial, identity.IsRemovalCode(regErr.Code)
	}
	return "", "", false
}

// servedByIdentifier finds the served device of a tunnel identifier.
func (r *deviceRunner) servedByIdentifier(identifier string) (identity.Ref, *servedDevice) {
	for ref, s := range r.served {
		if ref.Identity == identifier {
			return ref, s
		}
	}
	return identity.Ref{}, nil
}

// isConfigured reports whether identifier is a device of the current config.
func (r *deviceRunner) isConfigured(identifier string) bool {
	devices := r.configured.Load()
	return devices != nil && slices.ContainsFunc(*devices, func(d config.LocalDevice) bool { return d.Identity.Identity == identifier })
}

// notifyReload subscribes to reload signals; tests replace it.
var notifyReload = reloadSignals

// watchReload is the owner goroutine of the served devices: it runs
// handleEnds for queued device ends and, with load set, reloads on every
// reload signal, until ctx ends. A config that fails to load keeps the running
// devices and is logged. It subscribes
// first, so a signal sent before the agent runs is queued (not lost, and on
// Unix not the default SIGHUP exit), and handles it once the agent has
// started.
func (r *deviceRunner) watchReload(ctx context.Context, a *agent.Agent, load func() ([]config.LocalDevice, error)) {
	var sig <-chan os.Signal
	if load != nil {
		var stop func()
		sig, stop = notifyReload()
		defer stop()
	}
	select {
	case <-ctx.Done():
		return
	case <-a.Started():
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.endWake:
			r.handleEnds(ctx, a)
			continue
		case <-sig:
		}
		devices, err := load()
		if err != nil {
			r.logEvent(fmt.Sprintf("reload: kept the running config: %v", err))
			continue
		}
		r.reload(ctx, a, devices)
	}
}

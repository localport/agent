package cli

import (
	"context"
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
	"github.com/localport/agent/internal/tunnel"
)

// reloadSessionWait bounds how long a reload waits for the sessions of a
// changed device to end before it stops the device's tunnel.
const reloadSessionWait = 5 * time.Second

// servedDevice is one running device: its config entry, its session server
// (nil when sessions are off), its sessions lock, and its renewal and key
// refresh loops, which run under their own context so a reload can end them.
type servedDevice struct {
	local     config.LocalDevice
	sessions  *session.Server
	lock      *session.SessionsLock
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
// lock. The device's tunnel has stopped by then.
func (s *servedDevice) end() {
	if s.cancel != nil {
		s.cancel()
	}
	s.loops.Wait()
	_ = s.lock.Close()
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
	// configured is the device list the uploader accepts recordings for.
	configured atomic.Pointer[[]config.LocalDevice]
}

// build makes the runtime spec of d and its served state. A device that
// cannot start is logged and skipped (ok false).
func (r *deviceRunner) build(d config.LocalDevice) (spec config.DeviceSpec, ok bool) {
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
		served.refresher, served.lock = state.refresher, state.lock
		served.sessions, _ = spec.SessionHandler.(*session.Server)
	}
	if renews {
		served.renewer = &identity.Renewer{
			Store: r.store, Ref: d.Identity, OnEvent: r.logEvent, OnRefused: spec.Credential.RenewalRefused,
		}
	}
	r.served[d.Identity] = served
	return spec, true
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
		if d, ok := next[ref]; ok && d.Equal(s.local) {
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
	}
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
	r.configured.Store(&devices)
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
	if err != nil {
		r.logEvent(fmt.Sprintf("reload: %v", err))
		return
	}
	r.logEvent(fmt.Sprintf("reload: stopped %d device(s), started %d", len(ended), len(added)))
}

// isConfigured reports whether identifier is a device of the current config.
func (r *deviceRunner) isConfigured(identifier string) bool {
	devices := r.configured.Load()
	return devices != nil && slices.ContainsFunc(*devices, func(d config.LocalDevice) bool { return d.Identity.Identity == identifier })
}

// notifyReload subscribes to reload signals; tests replace it.
var notifyReload = reloadSignals

// watchReload runs reload on every reload signal until ctx ends. A config
// that fails to load keeps the running devices and is logged. It subscribes
// first, so a signal sent before the agent runs is queued (not lost, and on
// Unix not the default SIGHUP exit), and handles it once the agent has
// started.
func (r *deviceRunner) watchReload(ctx context.Context, a *agent.Agent, load func() ([]config.LocalDevice, error)) {
	sig, stop := notifyReload()
	defer stop()
	select {
	case <-ctx.Done():
		return
	case <-a.Started():
	}
	for {
		select {
		case <-ctx.Done():
			return
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

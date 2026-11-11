package agent

import (
	"context"
	"errors"
	"sync"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/netmon"
	"github.com/localport/agent/internal/proto"
	"github.com/localport/agent/internal/tunnel"
)

// Agent runs one tunnel.Tunnel per configured endpoint concurrently. Stop
// ends all of them; Apply swaps device tunnels while Run runs.
type Agent struct {
	cfg *config.Config

	mu sync.Mutex
	// idle is signalled, under mu, when live drops.
	idle    *sync.Cond
	tunnels []*tunnel.Tunnel
	runErrs []error
	// live counts running tunnel goroutines plus Apply calls in progress, so
	// Run does not return while Apply swaps the last device.
	live int
	// done marks every tunnel ended; Apply then starts nothing.
	done bool
	// exited holds, per running tunnel, a channel closed when its Run returns.
	exited map[*tunnel.Tunnel]chan struct{}
	// ctx and handler are Run's, for the tunnels Apply starts.
	ctx     context.Context
	handler tunnel.EventHandler
	// started is closed once Run holds ctx, so Apply no longer refuses.
	started chan struct{}
}

// ErrNotRunning refuses an Apply before Run or after every tunnel ended.
var ErrNotRunning = errors.New("the agent is not running")

func New(cfg *config.Config) *Agent {
	a := &Agent{cfg: cfg, exited: map[*tunnel.Tunnel]chan struct{}{}, started: make(chan struct{})}
	a.idle = sync.NewCond(&a.mu)
	return a
}

// Started is closed once Run has started its endpoints and Apply accepts
// changes. Run is called once per Agent.
func (a *Agent) Started() <-chan struct{} { return a.started }

// Run starts every endpoint with handler and blocks until all return.
//
// handler is a parameter because the renderer reads a.Tunnels and is built
// after the Agent, and each tunnel copies the handler at construction.
func (a *Agent) Run(ctx context.Context, handler tunnel.EventHandler) error {
	// One network monitor for the agent. A host network change makes every
	// tunnel probe its edge link, which detects a dead connection in seconds
	// instead of after the ~75s idle timeout. Event driven on Linux, BSD and
	// macOS, polled elsewhere.
	mon := netmon.New(nil)
	go mon.Run(ctx)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-mon.Events():
				for _, t := range a.Tunnels() {
					t.OnNetworkChange()
				}
			}
		}
	}()

	a.mu.Lock()
	a.ctx, a.handler = ctx, handler
	for _, spec := range a.cfg.Tunnels {
		// "default" is the flag path placeholder. Sending it would give every
		// unnamed invocation the same client name.
		clientName := spec.Name
		if clientName == "default" {
			clientName = ""
		}
		a.startLocked(tunnel.Options{
			Label:      spec.Name,
			Kind:       proto.KindTunnel,
			Token:      spec.Token,
			Edge:       spec.Edge,
			Local:      spec.Local,
			Protocol:   spec.Protocol,
			ClientName: clientName,
		})
	}
	for _, device := range a.cfg.Devices {
		a.startLocked(deviceOptions(device))
	}
	close(a.started)
	for a.live > 0 {
		a.idle.Wait()
	}
	a.done = true
	defer a.mu.Unlock()
	return errors.Join(a.runErrs...)
}

// Apply stops the device tunnels in stop, waits until each has returned, then
// calls build and starts one tunnel per spec it returns, returning them in
// order. build runs after the stopped tunnels have released what they held,
// so a replacement may open the same per-device state. Apply runs while Run
// runs and keeps Run from returning meanwhile. After Run has returned it stops
// and starts nothing and returns ErrNotRunning.
func (a *Agent) Apply(stop []*tunnel.Tunnel, build func() []config.DeviceSpec) ([]*tunnel.Tunnel, error) {
	a.mu.Lock()
	if a.ctx == nil || a.done {
		a.mu.Unlock()
		return nil, ErrNotRunning
	}
	a.live++
	waits := make([]chan struct{}, 0, len(stop))
	for _, t := range stop {
		if ch, ok := a.exited[t]; ok {
			waits = append(waits, ch)
		}
		a.removeLocked(t)
	}
	a.mu.Unlock()
	for _, t := range stop {
		t.Stop()
	}
	for _, ch := range waits {
		<-ch
	}
	var start []config.DeviceSpec
	if build != nil {
		start = build()
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	started := make([]*tunnel.Tunnel, 0, len(start))
	if a.ctx.Err() == nil {
		for _, spec := range start {
			started = append(started, a.startLocked(deviceOptions(spec)))
		}
	}
	a.live--
	a.idle.Broadcast()
	return started, nil
}

// startLocked starts one tunnel under Run's context and handler. a.mu is held.
func (a *Agent) startLocked(opts tunnel.Options) *tunnel.Tunnel {
	opts.AgentVersion = a.cfg.AgentVersion
	opts.Handler = a.handler
	opts.DisableMux = a.cfg.NoMux
	opts.DisableInspect = a.cfg.NoInspect
	t := tunnel.New(opts)
	exited := make(chan struct{})
	a.tunnels = append(a.tunnels, t)
	a.exited[t] = exited
	a.live++
	ctx := a.ctx
	go func() {
		err := t.Run(ctx)
		a.mu.Lock()
		if err != nil {
			a.runErrs = append(a.runErrs, err)
		}
		delete(a.exited, t)
		a.live--
		a.idle.Broadcast()
		a.mu.Unlock()
		close(exited)
	}()
	return t
}

func (a *Agent) removeLocked(t *tunnel.Tunnel) {
	for i, cur := range a.tunnels {
		if cur == t {
			a.tunnels = append(a.tunnels[:i:i], a.tunnels[i+1:]...)
			return
		}
	}
}

func deviceOptions(device config.DeviceSpec) tunnel.Options {
	opts := tunnel.Options{
		Label:          device.Name,
		Kind:           proto.KindDevice,
		Edge:           device.Edge,
		Host:           device.Host,
		ClientName:     device.Name,
		Identity:       device.Identity,
		AllowPorts:     device.AllowPorts,
		Capabilities:   device.Capabilities,
		Logins:         device.Logins,
		Desktop:        device.Desktop,
		SessionAuth:    device.SessionAuth,
		RunAsAgent:     device.RunAsAgent,
		FullDiskAccess: device.FullDiskAccess,
		// A nil interface value leaves sessions off.
		SessionHandler:   device.SessionHandler,
		ClipboardNotices: device.ClipboardNotices,
		HintRevoked:      device.HintRevoked,
	}
	// A nil *DeviceRegistrar in the interface would read as present.
	if device.Credential != nil {
		opts.Credential = device.Credential
	}
	return opts
}

func (a *Agent) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, t := range a.tunnels {
		t.Stop()
	}
}

// Tunnels returns a snapshot of the running tunnels. The TUI polls
// ActiveConnections through it.
func (a *Agent) Tunnels() []*tunnel.Tunnel {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*tunnel.Tunnel, len(a.tunnels))
	copy(out, a.tunnels)
	return out
}

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

// Agent fans a config out into one tunnel.Tunnel per endpoint and runs them
// concurrently. Stop tears all of them down.
type Agent struct {
	cfg     *config.Config
	handler tunnel.EventHandler

	mu      sync.Mutex
	tunnels []*tunnel.Tunnel
	runErrs []error
}

func New(cfg *config.Config, handler tunnel.EventHandler) *Agent {
	return &Agent{cfg: cfg, handler: handler}
}

// Run starts every endpoint and blocks until they have all returned.
func (a *Agent) Run(ctx context.Context) error {
	var wg sync.WaitGroup

	// One network monitor for the whole agent: on a host network change it
	// nudges every tunnel to fast-probe its edge link, so a change that killed
	// the connection is detected in seconds instead of the ~75s idle timeout.
	// Zero idle cost (event-driven on Linux/BSD/macOS; light poll elsewhere).
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

	start := func(opts tunnel.Options) {
		opts.AgentVersion = a.cfg.AgentVersion
		opts.Handler = a.handler
		opts.DisableMux = a.cfg.NoMux
		opts.DisableInspect = a.cfg.NoInspect
		t := tunnel.New(opts)

		a.mu.Lock()
		a.tunnels = append(a.tunnels, t)
		a.mu.Unlock()

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := t.Run(ctx); err != nil {
				a.mu.Lock()
				a.runErrs = append(a.runErrs, err)
				a.mu.Unlock()
			}
		}()
	}

	for _, spec := range a.cfg.Tunnels {
		// "default" is the flag path placeholder. Sending it would give every
		// unnamed invocation the same client name.
		clientName := spec.Name
		if clientName == "default" {
			clientName = ""
		}
		start(tunnel.Options{
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
		start(tunnel.Options{
			Label:      device.Name,
			Kind:       proto.KindDevice,
			Token:      device.Token,
			Edge:       device.Edge,
			Host:       device.Host,
			ClientName: device.Name,
		})
	}
	wg.Wait()
	a.mu.Lock()
	defer a.mu.Unlock()
	return errors.Join(a.runErrs...)
}

func (a *Agent) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, t := range a.tunnels {
		t.Stop()
	}
}

// SetHandler swaps the EventHandler. Useful when the renderer needs the
// Agent reference (e.g. for ActiveConnections polling) and therefore
// can't be supplied at construction time.
func (a *Agent) SetHandler(h tunnel.EventHandler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.handler = h
}

// Tunnels returns a snapshot of the currently-running tunnel pointers.
// The TUI uses this to poll ActiveConnections() without going through
// the event handler.
func (a *Agent) Tunnels() []*tunnel.Tunnel {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*tunnel.Tunnel, len(a.tunnels))
	copy(out, a.tunnels)
	return out
}

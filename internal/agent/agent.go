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
// ends all of them.
type Agent struct {
	cfg *config.Config

	mu      sync.Mutex
	tunnels []*tunnel.Tunnel
	runErrs []error
}

func New(cfg *config.Config) *Agent {
	return &Agent{cfg: cfg}
}

// Run starts every endpoint with handler and blocks until all return.
//
// handler is a parameter because the renderer reads a.Tunnels and is built
// after the Agent, and each tunnel copies the handler at construction.
func (a *Agent) Run(ctx context.Context, handler tunnel.EventHandler) error {
	var wg sync.WaitGroup

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

	start := func(opts tunnel.Options) {
		opts.AgentVersion = a.cfg.AgentVersion
		opts.Handler = handler
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
			AllowPorts: device.AllowPorts,
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

// Tunnels returns a snapshot of the running tunnels. The TUI polls
// ActiveConnections through it.
func (a *Agent) Tunnels() []*tunnel.Tunnel {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*tunnel.Tunnel, len(a.tunnels))
	copy(out, a.tunnels)
	return out
}

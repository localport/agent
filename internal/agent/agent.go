package agent

import (
	"context"
	"sync"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/tunnel"
)

type Agent struct {
	cfg     *config.Config
	handler tunnel.EventHandler

	mu      sync.Mutex
	tunnels []*tunnel.Tunnel
}

func New(cfg *config.Config, handler tunnel.EventHandler) *Agent {
	return &Agent{cfg: cfg, handler: handler}
}

// Run starts every endpoint and blocks until they have all returned.
func (a *Agent) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for _, spec := range a.cfg.Specs {
		for _, ep := range spec.Endpoints {
			t := tunnel.New(tunnel.Options{
				Label:    ep.Name,
				Token:    spec.Token,
				Edge:     spec.Edge,
				Local:    ep.Local,
				Protocol: ep.Protocol,
				UseTLS:   spec.UseTLS,
				Handler:  a.handler,
			})

			a.mu.Lock()
			a.tunnels = append(a.tunnels, t)
			a.mu.Unlock()

			wg.Add(1)
			go func(t *tunnel.Tunnel) {
				defer wg.Done()
				_ = t.Run(ctx)
			}(t)
		}
	}
	wg.Wait()
	return nil
}

func (a *Agent) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, t := range a.tunnels {
		t.Stop()
	}
}

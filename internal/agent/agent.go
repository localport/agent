package agent

import (
	"context"
	"sync"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/tunnel"
)

// Agent fans a config out into one tunnel.Tunnel per endpoint and runs them
// concurrently. Stop tears all of them down.
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
			// "default" is the placeholder name FromFlags assigns when the
			// user didn't pick one; passing it through to the edge would
			// have every CLI invocation collide on the same client name.
			clientName := ep.Name
			if clientName == "default" {
				clientName = ""
			}
			t := tunnel.New(tunnel.Options{
				Label:      ep.Name,
				Token:      spec.Token,
				Edge:       spec.Edge,
				Local:      ep.Local,
				Protocol:   ep.Protocol,
				ClientName: clientName,
				Handler:    a.handler,
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

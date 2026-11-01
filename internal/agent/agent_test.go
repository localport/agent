package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/tunnel"
)

// unreachableDevice is a device whose edge refuses every dial, so its tunnel
// keeps reconnecting until it is stopped.
func unreachableDevice(identity string) config.DeviceSpec {
	return config.DeviceSpec{Name: identity, Identity: identity, Edge: "127.0.0.1:1", Host: "127.0.0.1"}
}

func identities(a *Agent) []string {
	var out []string
	for _, t := range a.Tunnels() {
		out = append(out, t.Identity())
	}
	return out
}

// Apply stops a changed device's tunnel and starts its replacement, keeps the
// other device running, and keeps Run running through the swap of its only
// device.
func TestApplySwapsOnlyTheNamedDevice(t *testing.T) {
	a := New(&config.Config{Devices: []config.DeviceSpec{unreachableDevice("a.one"), unreachableDevice("b.two")}})
	if _, err := a.Apply(nil, nil); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Apply before Run = %v, want ErrNotRunning", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := make(chan error, 1)
	go func() { ran <- a.Run(ctx, nil) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(a.Tunnels()) < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the devices did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	keep, old := a.Tunnels()[1], a.Tunnels()[0]

	started, err := a.Apply([]*tunnel.Tunnel{old}, specs(unreachableDevice("a.one")))
	if err != nil || len(started) != 1 || started[0] == old {
		t.Fatalf("Apply = %v, %v", started, err)
	}
	if got := a.Tunnels(); len(got) != 2 || got[0] != keep || got[1] != started[0] {
		t.Fatalf("tunnels after Apply = %v, want the kept device then the new one", identities(a))
	}
	// Removing every device and adding one back keeps Run running.
	added, err := a.Apply(a.Tunnels(), specs(unreachableDevice("c.three")))
	if err != nil || len(added) != 1 {
		t.Fatalf("Apply = %v, %v", added, err)
	}
	select {
	case err := <-ran:
		t.Fatalf("Run returned during Apply: %v", err)
	default:
	}
	if got := identities(a); len(got) != 1 || got[0] != "c.three" {
		t.Fatalf("tunnels = %v, want [c.three]", got)
	}
	cancel()
	select {
	case <-ran:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if _, err := a.Apply(nil, nil); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Apply after Run = %v, want ErrNotRunning", err)
	}
}

func specs(s ...config.DeviceSpec) func() []config.DeviceSpec {
	return func() []config.DeviceSpec { return s }
}

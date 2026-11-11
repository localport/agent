package ui

import (
	"testing"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/proto"
	"github.com/localport/agent/internal/tunnel"
)

// Two devices with one name in two fleets get a row each, and events and
// live counters reach the device they came from.
func TestDevicesWithOneNameInTwoFleetsGetTwoRows(t *testing.T) {
	devices := []config.DeviceSpec{
		{Name: "gw-01", Identity: "01kpq7x2abcd34/device/tun1-gw-01", Host: "gw-01-north.eu.localport.dev"},
		{Name: "gw-01", Identity: "01kpq7x2abcd34/device/tun2-gw-01", Host: "gw-01-south.eu.localport.dev"},
	}
	ui := NewTUI()
	ui.mu.Lock()
	ui.registerLocked(&config.Config{Devices: devices})
	ui.mu.Unlock()
	var tunnels []*tunnel.Tunnel
	for _, d := range devices {
		tunnels = append(tunnels, tunnel.New(tunnel.Options{Kind: proto.KindDevice, Label: d.Name, Identity: d.Identity}))
	}
	ui.SetTunnelProvider(func() []*tunnel.Tunnel { return tunnels })

	ui.OnPortsUpdate(tunnels[1].EventKey(), []proto.DevicePort{{Port: 22, Protocol: "tcp"}})

	s := ui.snapshot()
	if len(s.tunnels) != 2 {
		t.Fatalf("rows = %d, want one per device", len(s.tunnels))
	}
	for i, ts := range s.tunnels {
		if ts.name != "gw-01" || ts.local != devices[i].Host {
			t.Fatalf("row %d = %q serving %q, want gw-01 serving %q", i, ts.name, ts.local, devices[i].Host)
		}
	}
	if len(s.tunnels[0].ports) != 0 || len(s.tunnels[1].ports) != 1 {
		t.Fatalf("ports = %v and %v, want the update on the second device only", s.tunnels[0].ports, s.tunnels[1].ports)
	}
	if len(s.stats) != 2 {
		t.Fatalf("live counters for %d tunnels, want 2", len(s.stats))
	}

	// A device added by a reload is named by OnStart, not by its identity.
	ui.OnStart("01kpq7x2abcd34/device/tun3-gw-02", "gw-02")
	if s := ui.snapshot(); len(s.tunnels) != 3 || s.tunnels[2].name != "gw-02" {
		t.Fatalf("rows after OnStart = %+v, want a third row named gw-02", s.tunnels)
	}
}

package ui

import (
	"strings"
	"testing"

	"github.com/localport/agent/internal/proto"
	"github.com/localport/agent/internal/tunnel"
)

func deviceState() tState {
	return tState{
		name:       "plc-01",
		tunnelName: "factory",
		region:     "ap",
		url:        "plc-01-factory.ap.localport.dev",
		urls:       []string{"plc-01-factory.ap.localport.dev"},
		local:      "192.168.1.100",
		state:      tunnel.StateActive,
		connected:  true,
		device:     true,
		ports: []proto.DevicePort{
			{Port: 80, Protocol: "http"},
			{Port: 502, Protocol: "tcp"},
		},
	}
}

func deviceSnap(ts tState) snap {
	return snap{
		cols:    100,
		rows:    30,
		palette: NewPalette(ColorOff),
		tunnels: []tState{ts},
		stats:   map[string]tunnel.Stats{ts.name: {BytesIn: 1400000, BytesOut: 430000, ConnectionsServed: 12}},
		conns:   map[string][]tunnel.ActiveConn{},
		reqs:    map[string][]tunnel.RequestInfo{},
	}
}

// A device header shows its ports in place of a protocol and URL.
func TestDeviceHeaderNamesTheDeviceAndItsPorts(t *testing.T) {
	got := strings.Join(renderHeader(deviceSnap(deviceState())), "\n")

	for _, want := range []string{
		"Device", "plc-01",
		"Fleet", "factory",
		"Asia Pacific",
		"Address", "plc-01-factory.ap.localport.dev",
		"Serving", "192.168.1.100",
		"Ports", "http 80", "tcp 502",
		"Connections", "12",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("header is missing %q:\n%s", want, got)
		}
	}
}

// A device with no open ports says so in the header.
func TestDeviceHeaderWarnsWhenNoPortsAreOpen(t *testing.T) {
	ts := deviceState()
	ts.ports = nil
	got := strings.Join(renderHeader(deviceSnap(ts)), "\n")
	if !strings.Contains(got, "no ports open") {
		t.Fatalf("header does not say the device serves nothing:\n%s", got)
	}
}

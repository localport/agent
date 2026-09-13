package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/localport/agent/internal/proto"
	"github.com/localport/agent/internal/tunnel"
)

func deviceState() tState {
	at := time.Date(2026, 9, 17, 15, 4, 5, 0, time.UTC)
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
		events: []devEvent{
			{at: at, kind: devConnOpen, port: 502, remote: "203.0.113.4:51000", consumer: "gw-ci"},
			{at: at.Add(time.Second), kind: devRequest, port: 80, method: "GET", path: "/health", status: 200, dur: 3 * time.Millisecond},
			{at: at.Add(7 * time.Second), kind: devConnClose, port: 502, remote: "203.0.113.4:51000", consumer: "gw-ci", dur: 7 * time.Second, bytes: 1400000},
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

// Connection and request rows share one log to keep their order, since a
// device serves tcp and http ports together.
func TestDeviceLogMergesConnectionsAndRequests(t *testing.T) {
	ts := deviceState()
	rows := renderDeviceLog(ts, 10, 100, NewPalette(ColorOff))
	if len(rows) != 4 {
		t.Fatalf("got %d rows, want header + 3", len(rows))
	}
	body := strings.Join(rows[1:], "\n")

	for _, want := range []string{
		"tcp 502", "open", "203.0.113.4", "gw-ci",
		"http 80", "GET", "/health", "200", "3ms",
		"close", "7s", HumanBytes(1400000),
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("log is missing %q:\n%s", want, body)
		}
	}
	// Oldest first.
	if strings.Index(body, "open") > strings.Index(body, "close") {
		t.Fatalf("rows are not in order:\n%s", body)
	}
	// The visitor source port is omitted.
	if strings.Contains(body, "51000") {
		t.Fatalf("the remote source port leaked into the log:\n%s", body)
	}
}

// With capacity 1 only the header fits, so the overflow marker must not
// address a body row.
func TestDeviceLogSqueezed(t *testing.T) {
	ts := deviceState()
	pal := NewPalette(ColorOff)
	for _, capacity := range []int{0, 1, 2, 3, 4} {
		rows := renderDeviceLog(ts, capacity, 100, pal)
		if capacity <= 0 && rows != nil {
			t.Fatalf("capacity=%d: want nil, got %d rows", capacity, len(rows))
		}
		if len(rows) > capacity {
			t.Fatalf("capacity=%d: produced %d rows, over budget", capacity, len(rows))
		}
	}
}

// The panel shows connection history.
func TestDevicePanelIsLabelledConnections(t *testing.T) {
	label, count := panelDivider(deviceSnap(deviceState()))
	if label != "connections" {
		t.Fatalf("panel label = %q", label)
	}
	if count != "12" {
		t.Fatalf("panel count = %q, want the lifetime connection count", count)
	}
}

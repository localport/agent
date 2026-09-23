package ui

import (
	"testing"

	"github.com/localport/agent/internal/ports"
	"github.com/localport/agent/internal/proto"
)

func TestFormatPortsMarksPortsOutsideTheCeiling(t *testing.T) {
	open := []proto.DevicePort{{Port: 22, Protocol: "tcp"}, {Port: 502, Protocol: "tcp"}}
	if got := formatPorts(open, ports.Ceiling{{From: 502, To: 502}}); got != "tcp 22 (blocked here) · tcp 502" {
		t.Errorf("with ceiling = %q", got)
	}
	if got := formatPorts(open, nil); got != "tcp 22 · tcp 502" {
		t.Errorf("without ceiling = %q", got)
	}
}

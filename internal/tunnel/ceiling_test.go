package tunnel

import (
	"net/http"
	"testing"

	"github.com/localport/agent/internal/ports"
	"github.com/localport/agent/internal/proto"
)

// A port outside the ceiling is refused before dialling, even when the edge
// asks for it.
func TestDialTargetRefusesAPortOutsideTheCeiling(t *testing.T) {
	tn := New(Options{
		Kind:       proto.KindDevice,
		Host:       "127.0.0.1",
		AllowPorts: ports.Ceiling{{From: 502, To: 502}},
	})
	tn.ports.Set(1, []proto.DevicePort{{Port: 22, Protocol: "tcp"}, {Port: 502, Protocol: "tcp"}})

	if _, status, err := tn.dialTarget(22); err == nil || status != http.StatusForbidden {
		t.Errorf("port 22 outside the ceiling: status=%d err=%v, want 403", status, err)
	}
	// Nothing listens on 502, so the dial fails, but not as a refusal.
	if _, status, _ := tn.dialTarget(502); status == http.StatusForbidden {
		t.Error("a port inside the ceiling was refused")
	}
}

// Register carries the ceiling only when one is set.
func TestWirePortRanges(t *testing.T) {
	if wirePortRanges(nil) != nil {
		t.Error("no ceiling must be absent on the wire")
	}
	got := wirePortRanges(ports.Ceiling{{From: 80, To: 80}, {From: 8000, To: 8100}})
	if len(got) != 2 || got[1].From != 8000 || got[1].To != 8100 {
		t.Errorf("wire = %+v", got)
	}
}

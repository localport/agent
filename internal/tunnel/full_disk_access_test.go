package tunnel

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/localport/agent/internal/proto"
)

// expectReport reads one device_report and returns its reading.
func expectReport(t *testing.T, edge *fakeEdge) string {
	t.Helper()
	var p proto.DeviceReportPayload
	if err := json.Unmarshal(edge.expect(t, proto.MsgDeviceReport), &p); err != nil {
		t.Fatal(err)
	}
	return p.FullDiskAccess
}

// The report loop sends a reading only when it differs from what the control
// session last reported, once per change and in order: a change between the
// Register and the loop's start goes out at once, an unchanged reading sends
// nothing, and the next Register carries the latest value.
func TestDeviceReportSendsEachChangeOnce(t *testing.T) {
	fda := NewFullDiskAccessState()
	fda.Set("granted")
	tn, edge := connectedTunnel(t, Options{Kind: proto.KindDevice, FullDiskAccess: fda})
	if reg := tn.registerPayload("n"); reg.FullDiskAccess != "granted" {
		t.Fatalf("register carried %q", reg.FullDiskAccess)
	}
	fda.attach(tn)
	defer fda.detach(tn)
	fda.Set("denied")
	sessionDone := make(chan struct{})
	loopDone := make(chan struct{})
	go func() { tn.reportLoop(sessionDone, "granted"); close(loopDone) }()
	if got := expectReport(t, edge); got != "denied" {
		t.Fatalf("first report %q, want the change since the Register", got)
	}
	fda.Set("denied")
	fda.Set("")
	fda.Set("granted")
	// The next frame is the change, not a repeat of the unchanged readings.
	if got := expectReport(t, edge); got != "granted" {
		t.Fatalf("second report %q, want granted", got)
	}
	if reg := tn.registerPayload("n"); reg.FullDiskAccess != "granted" {
		t.Fatalf("register after the reports carried %q", reg.FullDiskAccess)
	}
	close(sessionDone)
	select {
	case <-loopDone:
	case <-time.After(3 * time.Second):
		t.Fatal("the report loop outlived its session")
	}
}

// A nil state reads empty and ignores Set, so a device without logins and a
// tunnel report nothing.
func TestNilFullDiskAccessState(t *testing.T) {
	var s *FullDiskAccessState
	s.Set("granted")
	if s.Load() != "" {
		t.Fatal("a nil state held a reading")
	}
}

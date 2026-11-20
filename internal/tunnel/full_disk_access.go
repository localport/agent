package tunnel

import (
	"fmt"
	"sync"

	"github.com/localport/agent/internal/proto"
)

// FullDiskAccessState is the session launcher's latest Full Disk Access
// reading (macOS), shared by every device tunnel of one run. Each
// registration carries the current value; a change wakes every running
// device tunnel, whose report loop sends it as a device_report. The zero
// reading (empty, off macOS) is never stored.
type FullDiskAccessState struct {
	mu    sync.Mutex
	value string
	// tunnels are the running device tunnels to wake on a change.
	tunnels map[*Tunnel]struct{}
}

// NewFullDiskAccessState returns a state holding no reading.
func NewFullDiskAccessState() *FullDiskAccessState {
	return &FullDiskAccessState{tunnels: map[*Tunnel]struct{}{}}
}

// Load returns the latest reading; empty for a nil state or none held.
func (s *FullDiskAccessState) Load() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.value
}

// Set stores reading and, when it changed, wakes every running device tunnel.
// An empty reading is ignored. It never blocks on the network.
func (s *FullDiskAccessState) Set(reading string) {
	if s == nil || reading == "" {
		return
	}
	s.mu.Lock()
	if reading == s.value {
		s.mu.Unlock()
		return
	}
	s.value = reading
	woken := make([]*Tunnel, 0, len(s.tunnels))
	for t := range s.tunnels {
		woken = append(woken, t)
	}
	s.mu.Unlock()
	for _, t := range woken {
		t.wakeReport()
	}
}

// attach adds t to the tunnels a change wakes; detach removes it.
func (s *FullDiskAccessState) attach(t *Tunnel) {
	s.mu.Lock()
	s.tunnels[t] = struct{}{}
	s.mu.Unlock()
}

func (s *FullDiskAccessState) detach(t *Tunnel) {
	s.mu.Lock()
	delete(s.tunnels, t)
	s.mu.Unlock()
}

// wakeReport asks the report loop to compare and send; a pending wake
// already covers this one.
func (t *Tunnel) wakeReport() {
	select {
	case t.reportWake <- struct{}{}:
	default:
	}
}

// reportLoop sends the device's Full Disk Access reading whenever it differs
// from what this control session last reported: once at the start (a change
// between the Register and now) and at each wake, until the session ends.
// Sends are ordered, and each carries the latest value.
func (t *Tunnel) reportLoop(sessionDone <-chan struct{}, registered string) {
	reported := registered
	for {
		if current := t.opts.FullDiskAccess.Load(); current != "" && current != reported {
			c := t.snapshotConn()
			if c == nil {
				return
			}
			if err := c.SendDeviceReport(&proto.DeviceReportPayload{FullDiskAccess: current}); err != nil {
				t.signalDisconnected(fmt.Errorf("send a device report to the edge: %w", err))
				return
			}
			reported = current
		}
		select {
		case <-t.shutdown:
			return
		case <-sessionDone:
			return
		case <-t.reportWake:
		}
	}
}

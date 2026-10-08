package tunnel

import (
	"math"
	"testing"

	"github.com/localport/agent/internal/proto"
)

// Only a higher version applies. Older and equal versions are ignored.
func TestDevicePortsTakeTheHigherVersionOnly(t *testing.T) {
	p := newDevicePorts()

	if _, applied := p.Set(7, []proto.DevicePort{{Port: 502, Protocol: "tcp"}}); !applied {
		t.Fatal("the first set must apply")
	}
	if _, applied := p.Set(7, []proto.DevicePort{{Port: 80, Protocol: "http"}}); applied {
		t.Fatal("the same version must not replace the set")
	}
	if _, applied := p.Set(6, nil); applied {
		t.Fatal("an older version must not replace the set")
	}
	if _, open := p.Protocol(502); !open {
		t.Fatal("502 must still be open")
	}
	if _, open := p.Protocol(80); open {
		t.Fatal("80 was never applied")
	}
	if p.Version() != 7 {
		t.Fatalf("version = %d, want 7", p.Version())
	}

	removed, applied := p.Set(8, []proto.DevicePort{{Port: 80, Protocol: "http"}})
	if !applied {
		t.Fatal("a higher version must apply")
	}
	if _, open := p.Protocol(502); open {
		t.Fatal("502 left the set at version 8")
	}
	// Closed ports are returned.
	if len(removed) != 1 || removed[0] != 502 {
		t.Fatalf("removed = %v, want [502]", removed)
	}
}

// A repeated version 0 is ignored after the first. The server never sends 0.
func TestPortsSetRejectsARepeatedZeroVersion(t *testing.T) {
	p := newDevicePorts()

	removed, applied := p.Set(0, []proto.DevicePort{{Port: 502, Protocol: "tcp"}})
	if !applied || len(removed) != 0 {
		t.Fatalf("first update: applied=%v removed=%v", applied, removed)
	}
	if _, open := p.Protocol(502); !open {
		t.Fatal("port 502 should be open after the first update")
	}

	// The same version is ignored.
	removed, applied = p.Set(0, nil)
	if applied {
		t.Fatal("a repeated version 0 was applied")
	}
	if len(removed) != 0 {
		t.Fatalf("removed = %v, want none", removed)
	}
	if _, open := p.Protocol(502); !open {
		t.Fatal("port 502 was closed by a repeated version 0")
	}

	// A higher version still applies.
	if _, applied := p.Set(1, nil); !applied {
		t.Fatal("version 1 should apply over version 0")
	}
	if _, open := p.Protocol(502); open {
		t.Fatal("port 502 should be closed by version 1")
	}
}

// RegisterAck resets the list even after a MaxUint64 version.
func TestRegisterAckResetsPortsAfterMaxVersion(t *testing.T) {
	p := newDevicePorts()
	p.Set(math.MaxUint64, []proto.DevicePort{{Port: 22, Protocol: "tcp"}, {Port: 80, Protocol: "http"}})

	removed := p.Reset(1, []proto.DevicePort{{Port: 80, Protocol: "http"}})
	if len(removed) != 1 || removed[0] != 22 {
		t.Fatalf("removed = %v, want [22]", removed)
	}
	if _, open := p.Protocol(22); open {
		t.Fatal("port 22 is still open after the reset")
	}
	if p.Version() != 1 {
		t.Fatalf("version = %d, want 1", p.Version())
	}
}

// In-session updates with version <= current are ignored.
func TestPortsUpdateStillVersionCompared(t *testing.T) {
	p := newDevicePorts()
	p.Reset(5, []proto.DevicePort{{Port: 80, Protocol: "http"}})
	if _, applied := p.Set(4, nil); applied {
		t.Fatal("an older in-session update was applied")
	}
	if _, applied := p.Set(5, nil); applied {
		t.Fatal("a repeated in-session update was applied")
	}
	if _, applied := p.Set(6, nil); !applied {
		t.Fatal("a newer in-session update was refused")
	}
}

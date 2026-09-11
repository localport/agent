package tunnel

import (
	"sort"
	"sync"

	"github.com/localport/agent/internal/proto"
)

// devicePorts is the versioned set of ports the device serves, as set in the
// dashboard. Only a higher version replaces it, so late updates are ignored.
type devicePorts struct {
	mu sync.RWMutex
	// seeded is set by the first Set, so version 0 is accepted only once.
	seeded  bool
	version uint64
	ports   map[uint16]string // port -> tcp | http
}

func newDevicePorts() *devicePorts {
	return &devicePorts{ports: make(map[uint16]string)}
}

// Set replaces the ports when version is higher. It returns the closed ports
// and whether it applied the update.
func (p *devicePorts) Set(version uint64, ports []proto.DevicePort) (removed []uint16, applied bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seeded && version <= p.version {
		return nil, false
	}
	next := make(map[uint16]string, len(ports))
	for _, port := range ports {
		next[port.Port] = port.Protocol
	}
	for port := range p.ports {
		if _, stillOpen := next[port]; !stillOpen {
			removed = append(removed, port)
		}
	}
	p.ports, p.version, p.seeded = next, version, true
	return removed, true
}

// Protocol returns the protocol of port and whether it is open.
func (p *devicePorts) Protocol(port uint16) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	protocol, ok := p.ports[port]
	return protocol, ok
}

// Version returns the current port version.
func (p *devicePorts) Version() uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.version
}

// List returns the open ports sorted by number.
func (p *devicePorts) List() []proto.DevicePort {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]proto.DevicePort, 0, len(p.ports))
	for port, protocol := range p.ports {
		out = append(out, proto.DevicePort{Port: port, Protocol: protocol})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

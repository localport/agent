package ui

import (
	"fmt"
	"strings"

	"github.com/localport/agent/internal/ports"
	"github.com/localport/agent/internal/proto"
)

// formatPorts renders a device's open ports sorted by number and marks those
// outside allowed.
func formatPorts(open []proto.DevicePort, allowed ports.Ceiling) string {
	if len(open) == 0 {
		return "no ports open: edit this device in the dashboard"
	}
	parts := make([]string, len(open))
	for i, p := range open {
		parts[i] = fmt.Sprintf("%s %d", sanitizeForDisplay(p.Protocol), p.Port)
		if !allowed.Allows(p.Port) {
			parts[i] += " (blocked here)"
		}
	}
	return strings.Join(parts, " · ")
}

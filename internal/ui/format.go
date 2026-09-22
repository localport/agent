package ui

import (
	"fmt"
	"strings"

	"github.com/localport/agent/internal/proto"
)

// formatPorts renders a device's open ports sorted by number.
func formatPorts(ports []proto.DevicePort) string {
	if len(ports) == 0 {
		return "no ports open: edit this device in the dashboard"
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%s %d", sanitizeForDisplay(p.Protocol), p.Port)
	}
	return strings.Join(parts, " · ")
}

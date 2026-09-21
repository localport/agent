package ui

import (
	"errors"
	"strconv"
	"strings"

	"github.com/localport/agent/internal/proto"
	"github.com/localport/agent/internal/tunnel"
)

func errorCode(err error) string {
	var regErr *tunnel.RegistrationError
	if errors.As(err, &regErr) {
		return regErr.Code
	}
	return ""
}

func PolicyHint(lt proto.LimitType) string {
	switch lt {
	case proto.LimitBandwidth:
		return "bandwidth limit reached. Wait for the billing cycle to reset, or upgrade your plan"
	case proto.LimitClientConnections:
		return "client connection limit reached. Disconnect another client, or upgrade"
	case proto.LimitTunnelCount:
		return "tunnel limit reached. Remove a tunnel, or upgrade your plan"
	case proto.LimitNoPlan:
		return "team has no active plan. Subscribe or start a free trial from the dashboard"
	case proto.LimitPaymentDuePaused:
		return "payment is overdue. Update the payment method from the dashboard, then start the agent again"
	case proto.LimitBlocked:
		return "team account is blocked. Contact support"
	}
	return ""
}

// FirstEndpoint returns the public address to display. It prefers URLs, then
// PublicURL, then host:port for TCP and TLS tunnels that only report a port.
func FirstEndpoint(urls []string, publicURL, edgeAddr string, port uint16) string {
	if len(urls) > 0 {
		return urls[0]
	}
	if publicURL != "" {
		return publicURL
	}
	if port == 0 {
		return ""
	}
	host := edgeAddr
	if i := strings.LastIndex(edgeAddr, ":"); i >= 0 {
		host = edgeAddr[:i]
	}
	if host == "" {
		return ""
	}
	return host + ":" + strconv.Itoa(int(port))
}

// HumanBytes renders a byte count such as "1.2KB" or "8.4MB". One decimal at
// every scale keeps TUI column widths stable.
func HumanBytes(n int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)
	switch {
	case n < kb:
		return strconv.FormatInt(n, 10) + "B"
	case n < mb:
		return strconv.FormatFloat(float64(n)/kb, 'f', 1, 64) + "KB"
	case n < gb:
		return strconv.FormatFloat(float64(n)/mb, 'f', 1, 64) + "MB"
	default:
		return strconv.FormatFloat(float64(n)/gb, 'f', 1, 64) + "GB"
	}
}

package ui

import (
	"errors"
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
		return "bandwidth limit reached — wait for the billing cycle to reset or upgrade your plan"
	case proto.LimitClientConnections:
		return "client connection limit reached — disconnect another client or upgrade"
	case proto.LimitTunnelCount:
		return "tunnel limit reached — remove a tunnel or upgrade your plan"
	case proto.LimitNoPlan:
		return "team has no active plan — subscribe or start a free trial from the dashboard"
	case proto.LimitBlocked:
		return "team account is blocked — contact support"
	}
	return ""
}

// FirstEndpoint picks the most useful public address out of what the edge
// reported. URLs win, then PublicURL, then a synthesized host:port pair
// for raw TCP/TLS tunnels where the edge only returned a port.
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
	return host + ":" + itoa(int(port))
}

// itoa is a tiny strconv.Itoa replacement used by both PolicyHint and HumanBytes
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// HumanBytes renders a byte count as a short string ("1.2KB", "8.4MB").
func HumanBytes(n int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)
	switch {
	case n < kb:
		return itoa(int(n)) + "B"
	case n < mb:
		return formatFloat1(float64(n)/kb) + "KB"
	case n < gb:
		return formatFloat1(float64(n)/mb) + "MB"
	default:
		return formatFloat1(float64(n)/gb) + "GB"
	}
}

func formatFloat1(f float64) string {
	whole := int64(f)
	frac := int64((f - float64(whole)) * 10)
	if frac == 0 {
		return itoa(int(whole))
	}
	return itoa(int(whole)) + "." + string(byte('0'+frac))
}

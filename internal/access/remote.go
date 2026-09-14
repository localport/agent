package access

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// edgePort is the edge port for device access. All ports of a device share
// one mTLS connection to it.
const edgePort = "443"

// ParseDevice takes a device host and returns the host and the address to dial.
//
//	plc-01-factory.ap.localport.dev         → host, host:443
//	https://plc-01-factory.ap.localport.dev → host, host:443
//	plc-01.example.com:443                  → host, host:443
//
// A scheme and path are accepted and dropped so a pasted URL works. The
// protocol is set per port and does not depend on the address.
func ParseDevice(raw string) (host, addr string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("device address required")
	}
	if _, after, ok := strings.Cut(raw, "://"); ok {
		raw = after
	}
	raw = stripPathAndQuery(raw)

	host, port, err := splitHostPortLoose(raw)
	if err != nil {
		return "", "", err
	}
	if host == "" {
		return "", "", fmt.Errorf("device %q is missing a host", raw)
	}
	if port == "" {
		port = edgePort
	}
	return host, net.JoinHostPort(host, port), nil
}

// ParseForward parses one -L value in OpenSSH order, local port first.
//
//	5020:502   listen on 5020, reach the device's port 502
//	502        reach 502, on a local port the operating system picks
func ParseForward(raw, bindAddr string) (Forward, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Forward{}, errors.New("-L requires a port")
	}
	localText, remoteText, hasLocal := strings.Cut(raw, ":")
	if !hasLocal {
		remoteText, localText = localText, "0"
	}

	remote, err := parsePort(remoteText)
	if err != nil || remote == 0 {
		return Forward{}, fmt.Errorf("-L %s: device port must be 1-65535", raw)
	}
	local, err := parsePort(localText)
	if err != nil {
		return Forward{}, fmt.Errorf("-L %s: local port must be 0-65535", raw)
	}
	return Forward{
		LocalAddr:  net.JoinHostPort(bindAddr, strconv.Itoa(int(local))),
		RemotePort: remote,
	}, nil
}

func parsePort(text string) (uint16, error) {
	value, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || value < 0 || value > 65535 {
		return 0, errors.New("invalid port")
	}
	return uint16(value), nil
}

// stripPathAndQuery drops any trailing path, query or fragment.
func stripPathAndQuery(s string) string {
	for _, sep := range []string{"/", "?", "#"} {
		if i := strings.Index(s, sep); i >= 0 {
			s = s[:i]
		}
	}
	return s
}

// splitHostPortLoose splits host:port. The port is optional and a bracketed
// IPv6 literal is accepted.
func splitHostPortLoose(s string) (host, port string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", errors.New("empty address")
	}
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", "", fmt.Errorf("address %q is missing a closing bracket", s)
		}
		host = s[1:end]
		rest := s[end+1:]
		if strings.HasPrefix(rest, ":") {
			port = rest[1:]
		}
		return host, port, nil
	}
	if strings.Count(s, ":") > 1 {
		// A bare IPv6 literal carries no port.
		return s, "", nil
	}
	if host, port, ok := strings.Cut(s, ":"); ok {
		return host, port, nil
	}
	return s, "", nil
}

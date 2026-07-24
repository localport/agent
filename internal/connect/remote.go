package connect

import (
	"fmt"
	"net"
	"strings"
)

// ParseRemote normalizes a user-supplied remote endpoint into a canonical
// host:port that tls.Dial accepts. It exists so a URL copied straight from
// the tunnel dashboard can be pasted into `localport connect` unchanged.
//
// Accepted forms:
//
//	https://sub.eu.localport.dev            → sub.eu.localport.dev:443
//	http://sub.eu.localport.dev             → sub.eu.localport.dev:443
//	https://sub.eu.localport.dev:8443       → sub.eu.localport.dev:8443
//	tcp://sub.eu.localport.dev:11434         → sub.eu.localport.dev:11434
//	tls://sub.eu.localport.dev:11434         → sub.eu.localport.dev:11434
//	sub.eu.localport.dev:11434               → sub.eu.localport.dev:11434 (bare)
//
// mTLS is always terminated by the edge on the HTTPS port, so http/https URLs
// resolve to :443 unless the URL carries an explicit port. tcp/tls URLs and
// bare inputs must include the port because there is no protocol default.
func ParseRemote(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("remote address required")
	}

	if before, after, ok := strings.Cut(raw, "://"); ok {
		scheme := strings.ToLower(before)
		rest := stripPathAndQuery(after)
		host, port, err := splitHostPortLoose(rest)
		if err != nil {
			return "", err
		}
		if host == "" {
			return "", fmt.Errorf("remote %q is missing a host", raw)
		}
		switch scheme {
		case "http", "https":
			if port == "" {
				port = "443"
			}
		case "tcp", "tls":
			if port == "" {
				return "", fmt.Errorf("%s:// URL must include a port, e.g. %s://host:11434", scheme, scheme)
			}
		default:
			return "", fmt.Errorf("unsupported scheme %q (use https, http, tcp, or tls)", scheme)
		}
		return net.JoinHostPort(host, port), nil
	}

	host, port, err := splitHostPortLoose(stripPathAndQuery(raw))
	if err != nil {
		return "", err
	}
	if host == "" {
		return "", fmt.Errorf("remote %q is missing a host", raw)
	}
	if port == "" {
		return "", fmt.Errorf("remote %q needs a port (host:port) or a URL scheme (https://host, tcp://host:port)", raw)
	}
	return net.JoinHostPort(host, port), nil
}

// stripPathAndQuery drops any trailing path, query, or fragment so a pasted
// URL like https://host/foo?x=1 reduces to the authority component.
func stripPathAndQuery(s string) string {
	if j := strings.IndexAny(s, "/?#"); j >= 0 {
		return s[:j]
	}
	return s
}

// splitHostPortLoose splits host:port but tolerates a bare host (no colon),
// returning an empty port in that case. It only handles hostnames; an IPv6
// literal is not a valid tunnel remote and is rejected earlier.
func splitHostPortLoose(s string) (host, port string, err error) {
	if !strings.Contains(s, ":") {
		return s, "", nil
	}
	host, port, err = net.SplitHostPort(s)
	if err != nil {
		return "", "", fmt.Errorf("invalid host:port %q: %w", s, err)
	}
	return host, port, nil
}

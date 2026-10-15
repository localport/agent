package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// addrMemory maps a dial host to the IP of its last connection that completed
// TLS. dialEdge uses it only when resolving the host fails, never on NXDOMAIN.
// TLS still verifies the certificate against the hostname, so a stale IP fails
// the handshake. Process memory only.
type addrMemory struct {
	mu     sync.Mutex
	byHost map[string]string // dial host -> last verified IP
}

var lastGood = &addrMemory{byHost: make(map[string]string)}

// remember stores addr for host. IP literal hosts are skipped.
func (m *addrMemory) remember(host string, addr net.Addr) {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok || tcp.IP == nil || net.ParseIP(host) != nil {
		return
	}
	m.mu.Lock()
	m.byHost[host] = tcp.IP.String()
	m.mu.Unlock()
}

func (m *addrMemory) lookup(host string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ip, ok := m.byHost[host]
	return ip, ok
}

// lookupFailed reports a DNS error other than NXDOMAIN. NXDOMAIN is an answer
// and never falls back.
func lookupFailed(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && !dnsErr.IsNotFound
}

// dialEdge dials host:port and falls back to the remembered IP when the lookup
// fails. The caller's TLS ServerName is still host.
func dialEdge(ctx context.Context, d *net.Dialer, host, port string) (net.Conn, error) {
	ip, remembered := lastGood.lookup(host)
	if !remembered {
		return d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	}

	// an unresponsive nameserver fails only at the deadline, so the lookup
	// gets half the timeout and the fallback dial the rest.
	lookupCtx := ctx
	if deadline, ok := ctx.Deadline(); ok {
		var cancel context.CancelFunc
		lookupCtx, cancel = context.WithDeadline(ctx, time.Now().Add(time.Until(deadline)/2))
		defer cancel()
	}
	resolver := d.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	fallback := func(lookupErr error) (net.Conn, error) {
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
		if err != nil {
			// the lookup error is the root cause.
			return nil, lookupErr
		}
		return conn, nil
	}
	if _, err := resolver.LookupIPAddr(lookupCtx, host); err != nil {
		if !lookupFailed(err) {
			return nil, err
		}
		return fallback(err)
	}
	// DialContext resolves again and that lookup can fail on its own.
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil && lookupFailed(err) {
		return fallback(err)
	}
	return conn, err
}

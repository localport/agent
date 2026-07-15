// Package netmon watches for host network changes (new WiFi, cellular
// failover, VPN up/down, cable pull) and emits a debounced signal so the
// agent can proactively re-probe its edge connections instead of waiting out
// the ~75s control-link idle timeout.
//
// Detection is event-driven where the OS allows it: a netlink route socket on
// Linux (every kernel, including embedded/edge devices) and a PF_ROUTE socket
// on macOS/BSD, so the idle cost is zero: the watcher goroutine is parked in a
// blocking kernel read until the kernel pushes an event. Platforms without an
// event source (e.g. Windows) fall back to a light 10s address poll. Either
// way the raw OS wake-up is fed through one portable filter, the set of
// global-unicast IP addresses. Only a real change to that set emits; route
// churn, link-local noise, and loopback are ignored, so consumers never get a
// reconnect storm.
package netmon

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"
)

const (
	// debounceWindow coalesces the burst of events a single network change
	// produces (link down, addr removed, link up, addr added) into one signal.
	debounceWindow = 1500 * time.Millisecond

	// pollInterval is the address-poll cadence on platforms with no event
	// source. 10s trades a trivial amount of CPU for a much shorter detection
	// window than the 75s control-link idle timeout.
	pollInterval = 10 * time.Second

	// pollSafetyInterval is a slow backstop poll kept even when an event source
	// is active, so a source that dies silently (fd error, kernel quirk) still
	// can't hide a change longer than this. One InterfaceAddrs() call per
	// minute is negligible.
	pollSafetyInterval = 60 * time.Second

	// clockCheckInterval paces the sleep/wake detector: a wall-clock jump far
	// beyond the tick interval means the host slept. After sleep every socket
	// is presumed stale (peers reaped the silent connection, NAT state is
	// gone) even when the address set is unchanged, so a wake emits
	// unconditionally.
	clockCheckInterval = 10 * time.Second

	// wakeJumpThreshold is the wall-clock gap between ticks that counts as a
	// sleep. Well above scheduler jitter and routine NTP slew.
	wakeJumpThreshold = 30 * time.Second
)

// source is an OS-specific event trigger. watch blocks (parked in a kernel
// read) until the kernel reports a network event, at which point it wakes the
// monitor; it returns when ctx is done or the fd is closed. Close unblocks a
// parked watch. newSource returns nil on platforms without an event source.
type source interface {
	watch(ctx context.Context, wake chan<- struct{})
	Close() error
}

// Monitor emits on Events() whenever the host's global-unicast address set
// changes. Construct with New, drive with Run.
type Monitor struct {
	events chan struct{}
	logger *slog.Logger
}

// New builds a Monitor. A nil logger uses slog.Default().
func New(logger *slog.Logger) *Monitor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Monitor{
		events: make(chan struct{}, 1),
		logger: logger.With(slog.String("component", "netmon")),
	}
}

// Events delivers a signal per detected network change. The channel is
// buffered depth 1 and coalescing: a consumer that is slow simply sees one
// pending signal, never a backlog.
func (m *Monitor) Events() <-chan struct{} { return m.events }

// Run blocks until ctx is cancelled, translating OS network events (or, as a
// fallback, address polls) into debounced change signals. Call once.
func (m *Monitor) Run(ctx context.Context) {
	wake := make(chan struct{}, 1)

	src := newSource(m.logger)
	interval := pollInterval
	if src != nil {
		defer src.Close()
		go src.watch(ctx, wake)
		interval = pollSafetyInterval
		m.logger.Debug("network monitor using event source", slog.Duration("safety_poll", interval))
	} else {
		m.logger.Debug("network monitor using address poll", slog.Duration("interval", interval))
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	clockTick := time.NewTicker(clockCheckInterval)
	defer clockTick.Stop()

	last := snapshotAddrs()
	signal := func() {
		select {
		case m.events <- struct{}{}:
		default: // a signal is already pending; coalesce
		}
	}
	emit := func() {
		cur := snapshotAddrs()
		if cur == last {
			return
		}
		last = cur
		signal()
	}

	// Round(0) strips the monotonic reading so Sub measures WALL time. The
	// monotonic clock can freeze while the host sleeps, which is exactly the
	// gap this detector needs to see.
	wallLast := time.Now().Round(0)

	for {
		select {
		case <-ctx.Done():
			return
		case <-wake:
			m.debounce(ctx, wake)
			emit()
		case <-ticker.C:
			emit()
		case <-clockTick.C:
			now := time.Now().Round(0)
			if now.Sub(wallLast) > wakeJumpThreshold {
				m.logger.Debug("wake from sleep detected", slog.Duration("gap", now.Sub(wallLast)))
				last = snapshotAddrs() // resync; the emit below is unconditional
				signal()
			}
			wallLast = now
		}
	}
}

// debounce absorbs a burst of wake-ups: it waits debounceWindow, restarting the
// timer on each further wake, so a flurry of kernel events collapses into a
// single downstream emit.
func (m *Monitor) debounce(ctx context.Context, wake <-chan struct{}) {
	timer := time.NewTimer(debounceWindow)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-wake:
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(debounceWindow)
		case <-timer.C:
			return
		}
	}
}

// snapshotAddrs returns a stable key for the host's current global-unicast
// address set. An empty string (InterfaceAddrs failure) compares equal to
// itself so a transient enumeration error does not spuriously fire.
func snapshotAddrs() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	return addrKey(addrs)
}

// addrKey filters to routable (global-unicast) addresses and joins them into a
// sorted, comparable key. Loopback, link-local, multicast, and unspecified
// addresses are excluded because they never signal a real connectivity change.
func addrKey(addrs []net.Addr) string {
	ips := make([]string, 0, len(addrs))
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || !ip.IsGlobalUnicast() {
			continue
		}
		ips = append(ips, ip.String())
	}
	sort.Strings(ips)
	return strings.Join(ips, ",")
}

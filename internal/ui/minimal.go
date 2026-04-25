package ui

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/proto"
	"github.com/localport/agent/internal/tunnel"
)

// Minimal is a redraw-in-place status table aimed at constrained terminals
// (Docker logs viewers, serial consoles, embedded boards). It does not
// require a real TTY — Banner / Shutdown / event hooks all just redraw.
type Minimal struct {
	mu         sync.Mutex
	startedAt  time.Time
	edge       string
	endpoints  map[string]*endpointState
	labelWidth int
}

type endpointState struct {
	proto     string
	local     string
	state     string
	url       string
	subdomain string
	port      uint16
	lastEvent string
	lastErr   string
}

var _ tunnel.EventHandler = (*Minimal)(nil)

func NewMinimal() *Minimal {
	return &Minimal{
		startedAt:  time.Now(),
		endpoints:  make(map[string]*endpointState),
		labelWidth: 8,
	}
}

func (m *Minimal) Banner(version string, cfg *config.Config) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, spec := range cfg.Specs {
		if m.edge == "" {
			m.edge = spec.Edge
		}
		for _, ep := range spec.Endpoints {
			name := ep.Name
			if name == "" {
				name = "default"
			}
			m.endpoints[name] = &endpointState{
				proto:     ep.Protocol,
				local:     ep.Local,
				state:     "idle",
				lastEvent: "awaiting connection",
			}
			if len(name) > m.labelWidth {
				m.labelWidth = len(name)
			}
		}
	}
	m.renderLocked(version)
}

func (m *Minimal) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ep := range m.endpoints {
		ep.lastEvent = "shutting down"
		if ep.state != "stopped" {
			ep.state = "stopped"
		}
	}
	m.renderLocked("")
}

func (m *Minimal) OnStateChange(label string, _, to tunnel.State) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ep := m.ensure(label); ep != nil {
		ep.state = to.String()
		ep.lastEvent = "state: " + to.String()
	}
	m.renderLocked("")
}

func (m *Minimal) OnConnected(label string, info tunnel.Info) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ep := m.ensure(label); ep != nil {
		ep.state = "online"
		if u := firstURL(info); u != "" {
			ep.url = u
		}
		ep.subdomain = info.Subdomain
		ep.port = info.Port
		ep.lastEvent = "connected"
		ep.lastErr = ""
	}
	m.renderLocked("")
}

func (m *Minimal) OnDisconnected(label string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ep := m.ensure(label); ep != nil {
		ep.state = "disconnected"
		ep.lastEvent = "disconnected"
		if err != nil {
			ep.lastErr = err.Error()
		}
	}
	m.renderLocked("")
}

func (m *Minimal) OnError(label string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ep := m.ensure(label); ep != nil {
		ep.lastErr = err.Error()
		ep.lastEvent = "error"
	}
	m.renderLocked("")
}

func (m *Minimal) OnDataConn(label, _, _ string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ep := m.ensure(label); ep != nil {
		ep.lastEvent = "data connection"
	}
	m.renderLocked("")
}

func (m *Minimal) OnRedirect(label, from, to string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ep := m.ensure(label); ep != nil {
		ep.lastEvent = "redirect " + from + " -> " + to
	}
	m.edge = to
	m.renderLocked("")
}

func (m *Minimal) OnShutdownPolicy(label string, code string, lt proto.LimitType, _ bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ep := m.ensure(label); ep != nil {
		ep.state = "stopped"
		ep.lastEvent = "policy shutdown"
		var parts []string
		if code != "" {
			parts = append(parts, "code="+code)
		}
		if lt != "" {
			parts = append(parts, "type="+string(lt))
		}
		if hint := policyHint(code, lt); hint != "" {
			parts = append(parts, hint)
		}
		ep.lastErr = strings.Join(parts, " ")
	}
	m.renderLocked("")
}

// policyHint mirrors display.policyHint so the TUI shows the same guidance.
// Kept private here to avoid importing display just for a single helper.
func policyHint(code string, lt proto.LimitType) string {
	switch lt {
	case proto.LimitBandwidth:
		return "bandwidth limit — wait for reset or upgrade"
	case proto.LimitClientConnections:
		return "client limit — disconnect another client or upgrade"
	case proto.LimitTunnelCount:
		return "tunnel limit — remove a tunnel or upgrade"
	case proto.LimitNoPlan:
		return "no active plan — subscribe from the dashboard"
	}
	switch strings.ToUpper(code) {
	case "TK003":
		return "token invalid or expired"
	case "BL005":
		return "plan limit reached"
	case "BL007":
		return "bandwidth exceeded"
	case "BL010":
		return "feature not on your plan"
	}
	return ""
}

func (m *Minimal) ensure(label string) *endpointState {
	if label == "" {
		label = "default"
	}
	ep, ok := m.endpoints[label]
	if !ok {
		ep = &endpointState{state: "unknown"}
		m.endpoints[label] = ep
	}
	if len(label) > m.labelWidth {
		m.labelWidth = len(label)
	}
	return ep
}

const ruleWidth = 78

func (m *Minimal) renderLocked(version string) {
	if version == "" {
		version = "running"
	}
	uptime := max(time.Since(m.startedAt).Round(time.Second), 0)

	rule := strings.Repeat("-", ruleWidth)
	fmt.Fprint(os.Stderr, "\033[2J\033[H")
	fmt.Fprintf(os.Stderr, "localport tui | %s | edge: %s | uptime: %s\n", version, m.edge, uptime)
	fmt.Fprintln(os.Stderr, rule)
	fmt.Fprintf(os.Stderr, "%-*s  %-5s  %-12s  %-18s  %-22s  %s\n",
		m.labelWidth, "name", "proto", "state", "port/subdomain", "local", "url")
	fmt.Fprintln(os.Stderr, rule)

	for name, ep := range m.endpoints {
		fmt.Fprintf(os.Stderr, "%-*s  %-5s  %-12s  %-18s  %-22s  %s\n",
			m.labelWidth, name,
			trim(ep.proto, 5),
			trim(ep.state, 12),
			trim(portSubdomain(ep), 18),
			trim(ep.local, 22),
			trim(ep.url, 24))

		if ep.lastEvent != "" || ep.lastErr != "" {
			line := ep.lastEvent
			if ep.lastErr != "" {
				line = line + " | " + ep.lastErr
			}
			fmt.Fprintf(os.Stderr, "%s  %s\n",
				strings.Repeat(" ", m.labelWidth+2), trim(line, 70))
		}
	}

	fmt.Fprintln(os.Stderr, rule)
	fmt.Fprintln(os.Stderr, "ctrl+c to stop")
}

func portSubdomain(ep *endpointState) string {
	switch {
	case ep.port > 0 && ep.subdomain != "":
		return strconv.Itoa(int(ep.port)) + "/" + ep.subdomain
	case ep.port > 0:
		return strconv.Itoa(int(ep.port))
	case ep.subdomain != "":
		return ep.subdomain
	}
	return "-"
}

func trim(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + "…"
}

func firstURL(info tunnel.Info) string {
	if len(info.URLs) > 0 {
		return info.URLs[0]
	}
	if info.PublicURL != "" {
		return info.PublicURL
	}
	if info.Port == 0 || info.EdgeAddr == "" {
		return ""
	}
	host := info.EdgeAddr
	if h, _, err := net.SplitHostPort(info.EdgeAddr); err == nil {
		host = h
	}
	if host == "" {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(int(info.Port)))
}

package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/localport/agent/internal/security"

	"go.yaml.in/yaml/v4"
)

const edgePort = "443"

var regionHosts = map[string]string{
	"eu": "eu.localport.dev",
	"us": "us.localport.dev",
	"ap": "ap.localport.dev",
}

// Config is the validated runtime configuration.
type Config struct {
	// Tunnels publish a local service at a public URL.
	Tunnels []TunnelSpec
	// Devices join a fleet and serve the ports configured in the dashboard to
	// `localport access` clients.
	Devices []DeviceSpec

	// NoMux gives each inbound connection its own dial-back connection. Use it
	// on lossy links, where one dropped packet stalls every multiplexed stream.
	NoMux bool

	// NoInspect turns off HTTP request inspection.
	NoInspect bool

	// AgentVersion is the build version from ldflags, sent on registration.
	// It is not part of the YAML schema.
	AgentVersion string
}

// TunnelSpec is one published endpoint.
type TunnelSpec struct {
	Name     string
	Token    string
	Protocol string
	Local    string
	Edge     string
}

// DeviceSpec is one device on a fleet. Host is the address traffic is sent to
// and may name another machine on the local network. Ports come from the
// dashboard.
type DeviceSpec struct {
	Name  string
	Token string
	Host  string
	Edge  string
}

// DefaultDeviceHost is the device host when none is configured.
const DefaultDeviceHost = "localhost"

func (c *Config) Total() int { return len(c.Tunnels) + len(c.Devices) }

// fileConfig is the YAML schema.
type fileConfig struct {
	Version int          `yaml:"version"`
	Tunnels []tunnelFile `yaml:"tunnels,omitempty"`
	Fleets  []fleetFile  `yaml:"fleets,omitempty"`
}

type tunnelFile struct {
	Name     string `yaml:"name"`
	Token    string `yaml:"token"`
	Upstream string `yaml:"upstream"`
}

type fleetFile struct {
	Token   string       `yaml:"token"`
	Devices []deviceFile `yaml:"devices"`
}

type deviceFile struct {
	Name string `yaml:"name"`
	Host string `yaml:"host,omitempty"`
}

// Load reads the YAML at path, substitutes environment references and returns
// a validated Config.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	expanded, resolved, err := interpolate(string(raw))
	if err != nil {
		return nil, err
	}

	// Unknown keys are errors. A misspelled `host` would default to localhost
	// and proxy to the wrong machine.
	dec := yaml.NewDecoder(strings.NewReader(expanded))
	dec.KnownFields(true)

	var fc fileConfig
	if err := dec.Decode(&fc); err != nil {
		// Parser errors can quote a substituted secret. A value longer than
		// ten characters is quoted shortened, which RedactString cannot
		// match, so every quoted value is redacted as well.
		msg := security.RedactString(err.Error(), resolved...)
		if len(resolved) > 0 {
			msg = redactQuoted(msg)
		}
		return nil, fmt.Errorf("parse yaml: %s", msg)
	}
	return build(&fc)
}

// redactQuoted replaces every backtick-quoted span in a YAML error, which is
// how the parser quotes a value, with [REDACTED].
func redactQuoted(msg string) string {
	var b strings.Builder
	for {
		start := strings.IndexByte(msg, '`')
		if start < 0 {
			break
		}
		end := strings.IndexByte(msg[start+1:], '`')
		if end < 0 {
			break
		}
		b.WriteString(msg[:start])
		b.WriteString("`[REDACTED]`")
		msg = msg[start+1+end+1:]
	}
	b.WriteString(msg)
	return b.String()
}

// TunnelFromFlags builds a one-tunnel config from CLI arguments. Validation
// happens here so a typo fails immediately instead of causing a reconnect loop.
func TunnelFromFlags(token, region, local, proto, name string) (*Config, error) {
	if err := validRegion(region); err != nil {
		return nil, err
	}
	if name == "" {
		name = "default"
	} else if err := validTunnelName(name); err != nil {
		return nil, err
	}

	resolvedProto, resolvedLocal := ParseLocal(local, proto)
	switch resolvedProto {
	case "http", "tcp", "tls":
	default:
		return nil, fmt.Errorf("protocol %q is not one of http, tcp, tls", resolvedProto)
	}
	if resolvedLocal == "" {
		return nil, errors.New("no upstream address to forward to")
	}

	return &Config{Tunnels: []TunnelSpec{{
		Name:     name,
		Token:    token,
		Protocol: resolvedProto,
		Local:    resolvedLocal,
		Edge:     ResolveEdge(region),
	}}}, nil
}

// DeviceFromFlags builds a one-device config from CLI arguments.
func DeviceFromFlags(token, region, name, host string) (*Config, error) {
	if err := validRegion(region); err != nil {
		return nil, err
	}
	if !ValidDeviceName(name) {
		return nil, fmt.Errorf("--name %q is not a valid device name, expected 1-%d characters of "+
			"lowercase letters, digits and internal dashes", name, MaxDeviceNameLength)
	}

	host, err := parseDeviceHost(name, host)
	if err != nil {
		return nil, err
	}

	return &Config{Devices: []DeviceSpec{{
		Name:  name,
		Token: token,
		Host:  host,
		Edge:  ResolveEdge(region),
	}}}, nil
}

// MaxDeviceNameLength matches the control plane limit. A device name becomes a
// DNS label under the fleet's base label.
const MaxDeviceNameLength = 48

// ValidDeviceName reports whether the control plane accepts s as a device
// name. Invalid names are refused and not repaired, because a device name is
// an address and a grant target.
func ValidDeviceName(s string) bool {
	if s == "" || len(s) > MaxDeviceNameLength {
		return false
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

// DefaultDeviceName derives a device name from a hostname, for example
// "MacBook-Pro.local" becomes "macbook-pro". It returns "" when nothing usable
// remains.
func DefaultDeviceName(hostname string) string {
	if i := strings.IndexByte(hostname, '.'); i >= 0 {
		hostname = hostname[:i]
	}
	var b strings.Builder
	b.Grow(len(hostname))
	for _, r := range strings.ToLower(strings.TrimSpace(hostname)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case b.Len() > 0 && b.String()[b.Len()-1] != '-':
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > MaxDeviceNameLength {
		out = strings.TrimRight(out[:MaxDeviceNameLength], "-")
	}
	return out
}

// maxTunnelNameLength bounds the tunnel name shown in agent output.
const maxTunnelNameLength = 64

// validTunnelName refuses terminal control characters. Mixed case and spaces
// are allowed because the control plane slugifies the name.
func validTunnelName(name string) error {
	if len(name) > maxTunnelNameLength {
		return fmt.Errorf("--name is %d characters, over the %d character limit", len(name), maxTunnelNameLength)
	}
	if name != security.SanitizeDisplay(name) {
		return errors.New("--name contains control characters")
	}
	return nil
}

// validRegion accepts a single DNS label. ResolveEdge builds the dial host from
// it. Unknown regions are allowed so new regions need no agent release.
func validRegion(region string) error {
	if region == "" || ValidDeviceName(region) {
		return nil
	}
	return fmt.Errorf("--region %q is not a valid region, expected lowercase letters, "+
		"digits and internal dashes", region)
}

// ParseLocal splits a `local` value into (protocol, addr). A scheme in
// the URL wins over fallbackProto. A bare port ("18789") is rewritten
// to "localhost:18789". Empty input passes through.
func ParseLocal(local, fallbackProto string) (protocol, addr string) {
	local = strings.TrimSpace(local)
	if local == "" {
		return NormProto(fallbackProto), ""
	}
	if i := strings.Index(local, "://"); i > 0 {
		scheme := strings.ToLower(local[:i])
		switch scheme {
		case "http", "https", "tcp", "tls":
			return NormProto(scheme), normalizeLocalAddr(local[i+3:])
		}
	}
	return NormProto(fallbackProto), normalizeLocalAddr(local)
}

func normalizeLocalAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return addr
	}
	if _, err := strconv.Atoi(addr); err == nil {
		return "localhost:" + addr
	}
	return addr
}

// defaultRegion is only where the agent lands when no region is given. A
// tunnel's region lives on the tunnel, and an edge that does not hold it answers
// Register with a redirect.
const defaultRegion = "eu"

// ResolveEdge maps a region name to its agent-facing edge address.
// Regions use the "connect." subdomain so the dial host doubles as the
// TLS SNI the edge expects. TLS is mandatory on every region.
//
// An unknown region is passed through rather than refused, so a region added
// after this binary shipped still resolves.
func ResolveEdge(region string) string {
	if region == "" {
		region = defaultRegion
	}
	if host, ok := regionHosts[region]; ok {
		return "connect." + host + ":" + edgePort
	}
	return "connect." + region + ".localport.dev:" + edgePort
}

// NormProto lowercases the protocol and folds https into http.
func NormProto(p string) string {
	switch strings.ToLower(p) {
	case "", "https":
		return "http"
	default:
		return strings.ToLower(p)
	}
}

func build(fc *fileConfig) (*Config, error) {
	if fc.Version != 1 {
		return nil, fmt.Errorf("unsupported config version %d: this agent reads version 1, see https://localport.io/docs/configuration", fc.Version)
	}
	if len(fc.Tunnels) == 0 && len(fc.Fleets) == 0 {
		return nil, errors.New("the file lists no tunnels and no fleets")
	}

	out := &Config{}
	for i, t := range fc.Tunnels {
		built, err := buildTunnel(i+1, t)
		if err != nil {
			return nil, err
		}
		out.Tunnels = append(out.Tunnels, *built)
	}
	for i, f := range fc.Fleets {
		devices, err := buildFleet(i+1, f)
		if err != nil {
			return nil, err
		}
		out.Devices = append(out.Devices, devices...)
	}
	return out, nil
}

func buildTunnel(idx int, t tunnelFile) (*TunnelSpec, error) {
	if t.Name == "" {
		return nil, fmt.Errorf("tunnel %d: name is required", idx)
	}
	if t.Token == "" {
		return nil, fmt.Errorf("tunnel %q: token is required", t.Name)
	}
	if t.Upstream == "" {
		return nil, fmt.Errorf("tunnel %q: upstream is required", t.Name)
	}
	proto, local := ParseLocal(t.Upstream, "")
	switch proto {
	case "http", "tcp", "tls":
	default:
		return nil, fmt.Errorf("tunnel %q: upstream scheme %q is not one of http, tcp, tls", t.Name, proto)
	}
	return &TunnelSpec{
		Name:     t.Name,
		Token:    t.Token,
		Protocol: proto,
		Local:    local,
		Edge:     ResolveEdge(""),
	}, nil
}

func buildFleet(idx int, f fleetFile) ([]DeviceSpec, error) {
	if f.Token == "" {
		return nil, fmt.Errorf("fleet %d: token is required", idx)
	}
	if len(f.Devices) == 0 {
		return nil, fmt.Errorf("fleet %d: at least one device is required", idx)
	}

	seen := make(map[string]struct{}, len(f.Devices))
	out := make([]DeviceSpec, 0, len(f.Devices))
	for _, d := range f.Devices {
		if d.Name == "" {
			return nil, fmt.Errorf("fleet %d: every device needs a name", idx)
		}
		key := strings.ToLower(d.Name)
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("fleet %d: device %q is listed twice", idx, d.Name)
		}
		seen[key] = struct{}{}

		host, err := parseDeviceHost(d.Name, d.Host)
		if err != nil {
			return nil, err
		}
		out = append(out, DeviceSpec{Name: d.Name, Token: f.Token, Host: host, Edge: ResolveEdge("")})
	}
	return out, nil
}

// parseDeviceHost accepts an address without port or scheme. Ports and their
// protocols come from the dashboard.
func parseDeviceHost(name, host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return DefaultDeviceHost, nil
	}
	if strings.Contains(host, "://") {
		return "", fmt.Errorf("device %q: host takes an address without a scheme", name)
	}
	if hasExplicitPort(host) {
		return "", fmt.Errorf("device %q: host takes an address without a port, the dashboard opens the ports", name)
	}
	return host, nil
}

// hasExplicitPort reports whether host has a ":port" suffix. A bare IPv6
// literal is not treated as host:port.
func hasExplicitPort(host string) bool {
	idx := strings.LastIndex(host, ":")
	if idx < 0 || strings.Contains(host[idx+1:], "]") {
		return false
	}
	if strings.Count(host, ":") > 1 && !strings.HasPrefix(host, "[") {
		return false
	}
	_, err := strconv.Atoi(host[idx+1:])
	return err == nil
}

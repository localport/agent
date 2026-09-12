package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v4"
)

const edgePort = "443"

var regionHosts = map[string]string{
	"eu": "eu.localport.dev",
	"us": "us.localport.dev",
	"ap": "ap.localport.dev",
}

var envRef = regexp.MustCompile(`\$\{env\.([^}]+)\}`)

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

// Load reads the YAML at path, substitutes ${env.VAR} references, and
// returns a validated Config.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	expanded, missing := expand(string(raw))
	if len(missing) > 0 {
		return nil, fmt.Errorf("undefined env vars: %s", strings.Join(missing, ", "))
	}

	var fc fileConfig
	if err := yaml.Unmarshal([]byte(expanded), &fc); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	return build(&fc)
}

// FromFlags builds a one-tunnel config from CLI arguments. The name defaults
// to "default" when blank.
func FromFlags(token, region, local, proto, name string) *Config {
	if name == "" {
		name = "default"
	}
	resolvedProto, resolvedLocal := ParseLocal(local, proto)
	return &Config{Tunnels: []TunnelSpec{{
		Name:     name,
		Token:    token,
		Protocol: resolvedProto,
		Local:    resolvedLocal,
		Edge:     ResolveEdge(region),
	}}}
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
		return nil, fmt.Errorf("unsupported config version %d (only v1 is recognized)", fc.Version)
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

func expand(raw string) (string, []string) {
	var missing []string
	out := envRef.ReplaceAllStringFunc(raw, func(m string) string {
		name := envRef.FindStringSubmatch(m)[1]
		val, ok := os.LookupEnv(name)
		if !ok || val == "" {
			missing = append(missing, name)
		}
		return val
	})
	return out, missing
}

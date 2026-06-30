package config

import (
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

// Public runtime types.

type Config struct {
	Specs []Spec
}

type Spec struct {
	Token     string
	Region    string
	Edge      string
	Endpoints []Endpoint
}

type Endpoint struct {
	Name     string
	Protocol string
	Local    string
}

func (c *Config) TotalEndpoints() int {
	n := 0
	for _, s := range c.Specs {
		n += len(s.Endpoints)
	}
	return n
}

// YAML schema. Kept unexported so the parsed shape doesn't leak into callers.

type fileConfig struct {
	Version int    `yaml:"version"`
	Spec    *spec  `yaml:"spec,omitempty"`
	Specs   []spec `yaml:"specs,omitempty"`
}

type spec struct {
	Token     string     `yaml:"token"`
	Region    string     `yaml:"region,omitempty"`
	Endpoints []endpoint `yaml:"endpoints"`
}

type endpoint struct {
	Name  string `yaml:"name"`
	Proto string `yaml:"proto"`
	URL   string `yaml:"url"`
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

// FromFlags builds a single-endpoint config from CLI arguments. The
// endpoint name defaults to "default" when blank. `local` may carry a
// scheme prefix (tcp://, tls://, http://, https://) — when present, the
// scheme overrides `proto`. A bare numeric local is treated as a localhost port.
func FromFlags(token, region, local, proto, name string) *Config {
	if name == "" {
		name = "default"
	}
	resolvedProto, resolvedLocal := ParseLocal(local, proto)
	return &Config{
		Specs: []Spec{{
			Token:  token,
			Region: region,
			Edge:   ResolveEdge(region),
			Endpoints: []Endpoint{
				{Name: name, Protocol: resolvedProto, Local: resolvedLocal},
			},
		}},
	}
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

// ResolveEdge maps a region name to its agent-facing edge address.
// Regions use the "connect." subdomain so the dial host doubles as the
// TLS SNI the edge expects. TLS is mandatory on every region.
func ResolveEdge(region string) string {
	if region == "" {
		return "connect.edge.localport.dev:" + edgePort
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

	var specs []spec
	switch {
	case fc.Spec != nil && len(fc.Specs) > 0:
		return nil, fmt.Errorf("set either 'spec' or 'specs', not both")
	case fc.Spec != nil:
		specs = []spec{*fc.Spec}
	case len(fc.Specs) > 0:
		specs = fc.Specs
	default:
		return nil, fmt.Errorf("at least one spec is required")
	}

	out := &Config{}
	for i, s := range specs {
		built, err := buildSpec(i+1, s)
		if err != nil {
			return nil, err
		}
		out.Specs = append(out.Specs, *built)
	}
	return out, nil
}

func buildSpec(idx int, s spec) (*Spec, error) {
	if s.Token == "" {
		return nil, fmt.Errorf("spec %d: token is required", idx)
	}
	if len(s.Endpoints) == 0 {
		return nil, fmt.Errorf("spec %d: at least one endpoint is required", idx)
	}

	out := &Spec{
		Token:  s.Token,
		Region: s.Region,
		Edge:   ResolveEdge(s.Region),
	}
	for j, ep := range s.Endpoints {
		built, err := buildEndpoint(idx, j+1, ep)
		if err != nil {
			return nil, err
		}
		out.Endpoints = append(out.Endpoints, *built)
	}
	return out, nil
}

func buildEndpoint(specIdx, epIdx int, ep endpoint) (*Endpoint, error) {
	if ep.Name == "" {
		return nil, fmt.Errorf("spec %d endpoint %d: name is required", specIdx, epIdx)
	}
	if ep.URL == "" {
		return nil, fmt.Errorf("spec %d endpoint %q: url is required", specIdx, ep.Name)
	}
	proto, local := ParseLocal(ep.URL, ep.Proto)
	switch proto {
	case "http", "tcp", "tls":
	default:
		return nil, fmt.Errorf("spec %d endpoint %q: protocol %q is not one of http, tcp, tls", specIdx, ep.Name, ep.Proto)
	}
	return &Endpoint{Name: ep.Name, Protocol: proto, Local: local}, nil
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

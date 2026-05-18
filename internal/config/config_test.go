package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSingleSpec(t *testing.T) {
	t.Setenv("LP_TOKEN", "tok_test123")

	cfg := mustLoad(t, `
version: 1
spec:
  token: ${env.LP_TOKEN}
  region: eu
  endpoints:
    - name: web
      proto: http
      url: localhost:3000
    - name: db
      proto: tcp
      url: localhost:5432
`)

	if got, want := len(cfg.Specs), 1; got != want {
		t.Fatalf("specs = %d, want %d", got, want)
	}
	s := cfg.Specs[0]
	if s.Token != "tok_test123" {
		t.Errorf("token = %q, want tok_test123", s.Token)
	}
	if s.Edge != "connect.eu.localport.dev:443" {
		t.Errorf("edge = %q", s.Edge)
	}
	if s.Region != "eu" {
		t.Errorf("region = %q, want eu", s.Region)
	}
	if got, want := len(s.Endpoints), 2; got != want {
		t.Fatalf("endpoints = %d, want %d", got, want)
	}
	if s.Endpoints[0].Name != "web" || s.Endpoints[0].Protocol != "http" {
		t.Errorf("endpoint[0] = %+v", s.Endpoints[0])
	}
	if s.Endpoints[1].Local != "localhost:5432" {
		t.Errorf("endpoint[1].Local = %q", s.Endpoints[1].Local)
	}
}

func TestLoadMultipleSpecs(t *testing.T) {
	t.Setenv("LP_TOKEN_1", "tok_eu")
	t.Setenv("LP_TOKEN_2", "tok_us")

	cfg := mustLoad(t, `
version: 1
specs:
  - token: ${env.LP_TOKEN_1}
    region: eu
    endpoints:
      - name: server1
        proto: http
        url: localhost:4000
  - token: ${env.LP_TOKEN_2}
    region: us
    endpoints:
      - name: server2
        proto: tcp
        url: localhost:3400
`)

	if len(cfg.Specs) != 2 {
		t.Fatalf("specs = %d, want 2", len(cfg.Specs))
	}
	if cfg.Specs[0].Edge != "connect.eu.localport.dev:443" {
		t.Errorf("specs[0].Edge = %q", cfg.Specs[0].Edge)
	}
	if cfg.Specs[1].Edge != "connect.us.localport.dev:443" {
		t.Errorf("specs[1].Edge = %q", cfg.Specs[1].Edge)
	}
	if cfg.TotalEndpoints() != 2 {
		t.Errorf("TotalEndpoints = %d, want 2", cfg.TotalEndpoints())
	}
}

func TestLoadValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"missing env var", `
version: 1
spec:
  token: ${env.NONEXISTENT_VAR_12345}
  endpoints:
    - {name: web, proto: http, url: localhost:3000}
`},
		{"both spec and specs", `
version: 1
spec:
  token: tok
  endpoints: [{name: a, proto: http, url: localhost:3000}]
specs:
  - token: tok
    endpoints: [{name: b, proto: http, url: localhost:4000}]
`},
		{"missing token", `
version: 1
spec:
  endpoints: [{name: web, proto: http, url: localhost:3000}]
`},
		{"missing endpoint url", `
version: 1
spec:
  token: tok
  endpoints: [{name: web, proto: http}]
`},
		{"missing endpoint name", `
version: 1
spec:
  token: tok
  endpoints: [{proto: http, url: localhost:3000}]
`},
		{"invalid protocol", `
version: 1
spec:
  token: tok
  endpoints: [{name: web, proto: grpc, url: localhost:3000}]
`},
		{"empty endpoints", `
version: 1
spec:
  token: tok
  endpoints: []
`},
		{"no spec", `
version: 1
`},
		{"unsupported version", `
version: 2
spec:
  token: tok
  endpoints: [{name: web, proto: http, url: localhost:3000}]
`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := loadString(t, tc.yaml); err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestResolveEdge(t *testing.T) {
	cases := []struct {
		region string
		addr   string
	}{
		{"localhost", "localhost:443"},
		{"", "connect.edge.localport.dev:443"},
		{"eu", "connect.eu.localport.dev:443"},
		{"us", "connect.us.localport.dev:443"},
		{"ap", "connect.ap.localport.dev:443"},
		{"unknown", "connect.unknown.localport.dev:443"},
	}
	for _, tc := range cases {
		if got := ResolveEdge(tc.region); got != tc.addr {
			t.Errorf("ResolveEdge(%q) = %q, want %q", tc.region, got, tc.addr)
		}
	}
}

func TestNormProto(t *testing.T) {
	cases := map[string]string{
		"":      "http",
		"http":  "http",
		"HTTP":  "http",
		"https": "http",
		"tcp":   "tcp",
		"tls":   "tls",
		"TLS":   "tls",
	}
	for in, want := range cases {
		if got := NormProto(in); got != want {
			t.Errorf("NormProto(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFromFlags(t *testing.T) {
	cfg := FromFlags("tok_flag", "eu", "localhost:8080", "tcp", "myapp")
	s := cfg.Specs[0]
	if s.Token != "tok_flag" || s.Edge != "connect.eu.localport.dev:443" {
		t.Errorf("spec = %+v", s)
	}
	if s.Endpoints[0].Name != "myapp" || s.Endpoints[0].Protocol != "tcp" {
		t.Errorf("endpoint = %+v", s.Endpoints[0])
	}
}

func TestFromFlagsDefaults(t *testing.T) {
	cfg := FromFlags("tok", "", "localhost:8080", "http", "")
	s := cfg.Specs[0]
	if s.Endpoints[0].Name != "default" {
		t.Errorf("name = %q, want default", s.Endpoints[0].Name)
	}
	if s.Edge != "connect.edge.localport.dev:443" {
		t.Errorf("edge = %q", s.Edge)
	}
}

func TestLoadRegionFallback(t *testing.T) {
	cfg := mustLoad(t, `
version: 1
spec:
  token: tok
  endpoints: [{name: web, proto: http, url: localhost:3000}]
`)
	if cfg.Specs[0].Edge != "connect.edge.localport.dev:443" {
		t.Errorf("edge = %q, want default fallback", cfg.Specs[0].Edge)
	}
}

func TestTotalEndpoints(t *testing.T) {
	cfg := &Config{Specs: []Spec{
		{Endpoints: []Endpoint{{}, {}}},
		{Endpoints: []Endpoint{{}}},
	}}
	if got := cfg.TotalEndpoints(); got != 3 {
		t.Errorf("TotalEndpoints = %d, want 3", got)
	}
}

func mustLoad(t *testing.T, yaml string) *Config {
	t.Helper()
	cfg, err := loadString(t, yaml)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func loadString(t *testing.T, yaml string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return Load(path)
}

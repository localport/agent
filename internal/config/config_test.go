package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "localport.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadReadsTunnelsAndDevices(t *testing.T) {
	t.Setenv("FLEET_TOKEN", "fleet-token")
	path := writeConfig(t, `
version: 1
tunnels:
  - name: api
    token: tunnel-token
    upstream: http://localhost:8080
  - name: db
    token: tunnel-token
    upstream: tcp://localhost:5432
fleets:
  - token: ${FLEET_TOKEN}
    devices:
      - name: hub
      - name: plc-01
        host: 192.168.1.100
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Tunnels) != 2 || len(cfg.Devices) != 2 {
		t.Fatalf("got %d tunnels and %d devices", len(cfg.Tunnels), len(cfg.Devices))
	}
	if cfg.Tunnels[0].Protocol != "http" || cfg.Tunnels[0].Local != "localhost:8080" {
		t.Fatalf("tunnel 1 = %+v", cfg.Tunnels[0])
	}
	if cfg.Tunnels[1].Protocol != "tcp" {
		t.Fatalf("tunnel 2 protocol = %q", cfg.Tunnels[1].Protocol)
	}
	// A device with no host serves this machine.
	if cfg.Devices[0].Host != DefaultDeviceHost {
		t.Fatalf("device 1 host = %q", cfg.Devices[0].Host)
	}
	if cfg.Devices[1].Host != "192.168.1.100" || cfg.Devices[1].Token != "fleet-token" {
		t.Fatalf("device 2 = %+v", cfg.Devices[1])
	}
	if cfg.Total() != 4 {
		t.Fatalf("total = %d", cfg.Total())
	}
}

func TestLoadRefusesBadFiles(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"version 2", "version: 2\ntunnels: []\n"},
		{"nothing to run", "version: 1\n"},
		{"tunnel without upstream", "version: 1\ntunnels:\n  - name: api\n    token: t\n"},
		{"fleet without devices", "version: 1\nfleets:\n  - token: t\n    devices: []\n"},
		{"duplicate device", "version: 1\nfleets:\n  - token: t\n    devices:\n      - name: gw\n      - name: GW\n"},
		{"host with port", "version: 1\nfleets:\n  - token: t\n    devices:\n      - name: gw\n        host: 10.0.0.2:502\n"},
		{"host with scheme", "version: 1\nfleets:\n  - token: t\n    devices:\n      - name: gw\n        host: tcp://10.0.0.2\n"},
		{"allow_ports out of range", "version: 1\nfleets:\n  - token: t\n    devices:\n      - name: gw\n        allow_ports: [70000]\n"},
		{"allow_ports reversed range", "version: 1\nfleets:\n  - token: t\n    devices:\n      - name: gw\n        allow_ports: [\"100-90\"]\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, tc.body)); err == nil {
				t.Fatal("want the file refused")
			}
		})
	}
}

// A bare IPv6 device host is not parsed as host:port.
func TestDeviceHostAcceptsIPv6(t *testing.T) {
	cfg, err := Load(writeConfig(t, "version: 1\nfleets:\n  - token: t\n    devices:\n      - name: gw\n        host: fd00::1\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Devices[0].Host != "fd00::1" {
		t.Fatalf("host = %q", cfg.Devices[0].Host)
	}
}

// allow_ports takes bare ports and quoted ranges in one list.
func TestDeviceAllowPortsFromYAML(t *testing.T) {
	cfg, err := Load(writeConfig(t, "version: 1\nfleets:\n  - token: t\n    devices:\n      - name: gw\n        allow_ports: [502, 80, \"8000-8100\"]\n      - name: open\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.Devices[0].AllowPorts.String(); got != "80,502,8000-8100" {
		t.Errorf("allow_ports = %q", got)
	}
	if cfg.Devices[1].AllowPorts != nil {
		t.Error("a device without allow_ports must have no ceiling")
	}
}

func TestInterpolate(t *testing.T) {
	t.Setenv("SET", "value")
	t.Setenv("EMPTY", "")

	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "plain", in: "${SET}", want: "value"},
		{name: "unset", in: "${MISSING}", wantErr: true},
		{name: "empty counts as unset", in: "${EMPTY}", wantErr: true},
		{name: "default used", in: "${MISSING:-fallback}", want: "fallback"},
		{name: "default ignored", in: "${SET:-fallback}", want: "value"},
		{name: "empty takes the default", in: "${EMPTY:-fallback}", want: "fallback"},
		{name: "message", in: "${MISSING:?set this first}", wantErr: true},
		{name: "message satisfied", in: "${SET:?set this first}", want: "value"},
		{name: "literal dollar", in: "$$SET", want: "$SET"},
		{name: "bare dollar", in: "cost $5", want: "cost $5"},
		{name: "unterminated", in: "${SET", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := interpolate(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("interpolate: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// The error names the unset variable.
func TestInterpolateMessageNamesTheVariable(t *testing.T) {
	_, _, err := interpolate("${FLEET_TOKEN:?set FLEET_TOKEN}")
	if err == nil {
		t.Fatal("want an error")
	}
	if got := err.Error(); got != "FLEET_TOKEN: set FLEET_TOKEN" {
		t.Fatalf("error = %q", got)
	}
}

func TestParseLocal(t *testing.T) {
	cases := []struct{ in, fallback, wantProto, wantAddr string }{
		{"3000", "", "http", "localhost:3000"},
		{"localhost:3000", "", "http", "localhost:3000"},
		{"tcp://localhost:5432", "", "tcp", "localhost:5432"},
		{"tls://10.0.0.1:8883", "http", "tls", "10.0.0.1:8883"},
		{"https://localhost:8443", "", "http", "localhost:8443"},
	}
	for _, tc := range cases {
		proto, addr := ParseLocal(tc.in, tc.fallback)
		if proto != tc.wantProto || addr != tc.wantAddr {
			t.Fatalf("ParseLocal(%q) = (%q, %q), want (%q, %q)", tc.in, proto, addr, tc.wantProto, tc.wantAddr)
		}
	}
}

// A parse error must not quote a substituted secret, whole or shortened. The
// parser quotes a value that fails to decode and shortens one over ten
// characters to its first seven.
func TestLoadRedactsResolvedSecretsFromParseErrors(t *testing.T) {
	t.Setenv("LOCALPORT_TOKEN", "tok_supersecretvalue")
	t.Setenv("LOCALPORT_SHORT", "hunter2")

	for _, body := range []string{
		"version: ${LOCALPORT_TOKEN}\n",
		"version: ${LOCALPORT_SHORT}\n",
	} {
		path := filepath.Join(t.TempDir(), "localport.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		_, err := Load(path)
		if err == nil {
			t.Fatalf("want %q refused", body)
		}
		for _, secret := range []string{"tok_sup", "hunter2"} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("the error carries %q: %v", secret, err)
			}
		}
	}
}

// Unknown keys are errors. A mistyped `host` would default to localhost.
func TestLoadRejectsUnknownFields(t *testing.T) {
	cases := []struct {
		name, yaml, want string
	}{
		{
			name: "device host typo",
			yaml: "version: 1\nfleets:\n  - token: tok\n    devices:\n      - name: plc-01\n        hosts: 192.168.1.100\n",
			want: "hosts",
		},
		{
			name: "tunnel upstream typo",
			yaml: "version: 1\ntunnels:\n  - name: web\n    token: tok\n    upsteam: http://localhost:3000\n",
			want: "upsteam",
		},
		{
			name: "top level typo",
			yaml: "version: 1\ntunnel:\n  - name: web\n",
			want: "tunnel",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "localport.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatal("expected the unknown field to be refused")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error should name %q, got %q", tc.want, err)
			}
		})
	}
}

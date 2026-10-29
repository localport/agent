package config

import (
	"strings"
	"testing"
)

// Flag values are validated before dialing.
func TestTunnelFromFlagsRefusesBadValues(t *testing.T) {
	for name, c := range map[string]struct {
		region, local, proto, tunnel string
	}{
		"unknown protocol":        {local: "3000", proto: "ftp"},
		"region with a traversal": {region: "../evil", local: "3000", proto: "http"},
		"region with a separator": {region: "eu/x", local: "3000", proto: "http"},
		"region with a dot":       {region: "eu.localport.dev", local: "3000", proto: "http"},
		"uppercase region":        {region: "EU", local: "3000", proto: "http"},
		"region with a space":     {region: "eu us", local: "3000", proto: "http"},
		"no upstream":             {local: "", proto: "http"},
		"escape in the name":      {local: "3000", proto: "http", tunnel: "api\x1b]0;x\a"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := TunnelFromFlags("tok", c.region, c.local, c.proto, c.tunnel); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// An unknown region still resolves.
func TestTunnelFromFlagsAcceptsAnUnknownRegion(t *testing.T) {
	cfg, err := TunnelFromFlags("tok", "sa", "3000", "http", "")
	if err != nil {
		t.Fatalf("unknown region refused: %v", err)
	}
	if got := cfg.Tunnels[0].Edge; got != "connect.sa.localport.dev:443" {
		t.Fatalf("edge = %q, want the derived sa host", got)
	}
}

// Tunnel names allow mixed case and spaces. The control plane slugifies them.
func TestTunnelFromFlagsAcceptsAReadableName(t *testing.T) {
	cfg, err := TunnelFromFlags("tok", "eu", "3000", "http", "My API")
	if err != nil {
		t.Fatalf("readable name refused: %v", err)
	}
	if cfg.Tunnels[0].Name != "My API" {
		t.Fatalf("name = %q, want it carried through", cfg.Tunnels[0].Name)
	}
}

func TestTunnelFromFlagsRefusesAnOverlongName(t *testing.T) {
	if _, err := TunnelFromFlags("tok", "eu", "3000", "http", strings.Repeat("a", 65)); err == nil {
		t.Fatal("accepted a name over the limit")
	}
}

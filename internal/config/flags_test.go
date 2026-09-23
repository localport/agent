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

// Invalid device names are refused and not repaired.
func TestDeviceFromFlagsRefusesANameThatIsNotALabel(t *testing.T) {
	for _, name := range []string{
		"", "GW-01", "gw 01", "gw.01", "-gw", "gw-", "gw/01",
		strings.Repeat("a", MaxDeviceNameLength+1),
	} {
		if _, err := DeviceFromFlags("tok", "eu", name, "", ""); err == nil {
			t.Errorf("accepted device name %q", name)
		}
	}
}

func TestDeviceFromFlagsRefusesAHostCarryingSchemeOrPort(t *testing.T) {
	for _, host := range []string{"tcp://192.168.1.10", "http://box", "192.168.1.10:502"} {
		if _, err := DeviceFromFlags("tok", "eu", "gw-01", host, ""); err == nil {
			t.Errorf("accepted host %q", host)
		}
	}
}

func TestDeviceFromFlagsDefaultsTheHost(t *testing.T) {
	cfg, err := DeviceFromFlags("tok", "eu", "gw-01", "", "")
	if err != nil {
		t.Fatalf("device: %v", err)
	}
	if cfg.Devices[0].Host != DefaultDeviceHost {
		t.Fatalf("host = %q, want %q", cfg.Devices[0].Host, DefaultDeviceHost)
	}
}

func TestDeviceFromFlagsParsesAllowPorts(t *testing.T) {
	cfg, err := DeviceFromFlags("tok", "eu", "gw-01", "", "8000-8100,502")
	if err != nil {
		t.Fatalf("device: %v", err)
	}
	if got := cfg.Devices[0].AllowPorts.String(); got != "502,8000-8100" {
		t.Errorf("allow ports = %q", got)
	}
	if cfg, _ := DeviceFromFlags("tok", "eu", "gw-01", "", ""); cfg.Devices[0].AllowPorts != nil {
		t.Error("no --allow-ports must mean no ceiling")
	}
	if _, err := DeviceFromFlags("tok", "eu", "gw-01", "", "0,70000"); err == nil {
		t.Error("accepted out-of-range ports")
	}
}

// Hostnames with a domain or capitals are repaired into a device name.
func TestDefaultDeviceNameRepairsAHostname(t *testing.T) {
	for in, want := range map[string]string{
		"MacBook-Pro.local":     "macbook-pro",
		"gw-01":                 "gw-01",
		"WIN-SERVER01":          "win-server01",
		"ip-10-0-1-5.ec2":       "ip-10-0-1-5",
		"  Vikas MBP  ":         "vikas-mbp",
		"_host_":                "host",
		"host--name":            "host-name",
		"...":                   "",
		"":                      "",
		strings.Repeat("A", 60): strings.Repeat("a", MaxDeviceNameLength),
	} {
		if got := DefaultDeviceName(in); got != want {
			t.Errorf("DefaultDeviceName(%q) = %q, want %q", in, got, want)
		}
	}
}

// A repaired hostname always passes ValidDeviceName.
func TestDefaultDeviceNameOutputIsAlwaysValid(t *testing.T) {
	for _, in := range []string{
		"MacBook-Pro.local", "WIN-SERVER01", "  spaced  name ", "---", "ünïcødé-böx",
		strings.Repeat("a-", 60), "9", "-lead", "trail-",
	} {
		got := DefaultDeviceName(in)
		if got == "" {
			continue
		}
		if !ValidDeviceName(got) {
			t.Errorf("DefaultDeviceName(%q) = %q, which ValidDeviceName refuses", in, got)
		}
	}
}

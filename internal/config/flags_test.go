package config

import (
	"strings"
	"testing"
)

// Invalid device names are refused and not repaired.
func TestDeviceFromFlagsRefusesANameThatIsNotALabel(t *testing.T) {
	for _, name := range []string{
		"", "GW-01", "gw 01", "gw.01", "-gw", "gw-", "gw/01",
		strings.Repeat("a", MaxDeviceNameLength+1),
	} {
		if _, err := DeviceFromFlags("tok", "eu", name, ""); err == nil {
			t.Errorf("accepted device name %q", name)
		}
	}
}

func TestDeviceFromFlagsRefusesAHostCarryingSchemeOrPort(t *testing.T) {
	for _, host := range []string{"tcp://192.168.1.10", "http://box", "192.168.1.10:502"} {
		if _, err := DeviceFromFlags("tok", "eu", "gw-01", host); err == nil {
			t.Errorf("accepted host %q", host)
		}
	}
}

func TestDeviceFromFlagsDefaultsTheHost(t *testing.T) {
	cfg, err := DeviceFromFlags("tok", "eu", "gw-01", "")
	if err != nil {
		t.Fatalf("device: %v", err)
	}
	if cfg.Devices[0].Host != DefaultDeviceHost {
		t.Fatalf("host = %q, want %q", cfg.Devices[0].Host, DefaultDeviceHost)
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

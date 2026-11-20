package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/tunnel"
)

// unreachableDevice is a device whose edge refuses every dial, so its tunnel
// keeps reconnecting until it is stopped.
func unreachableDevice(identity string) config.DeviceSpec {
	return config.DeviceSpec{Name: identity, Identity: identity, Edge: "127.0.0.1:1", Host: "127.0.0.1"}
}

func identities(a *Agent) []string {
	var out []string
	for _, t := range a.Tunnels() {
		out = append(out, t.Identity())
	}
	return out
}

// Apply replaces only a changed device's tunnel, keeps the other device
// running, and keeps Run running while its only device is swapped.
func TestApplySwapsOnlyTheNamedDevice(t *testing.T) {
	a := New(&config.Config{Devices: []config.DeviceSpec{unreachableDevice("a.one"), unreachableDevice("b.two")}})
	if _, err := a.Apply(nil, nil); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Apply before Run = %v, want ErrNotRunning", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := make(chan error, 1)
	go func() { ran <- a.Run(ctx, nil) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(a.Tunnels()) < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the devices did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	keep, old := a.Tunnels()[1], a.Tunnels()[0]

	started, err := a.Apply([]*tunnel.Tunnel{old}, specs(unreachableDevice("a.one")))
	if err != nil || len(started) != 1 || started[0] == old {
		t.Fatalf("Apply = %v, %v", started, err)
	}
	if got := a.Tunnels(); len(got) != 2 || got[0] != keep || got[1] != started[0] {
		t.Fatalf("tunnels after Apply = %v, want the kept device then the new one", identities(a))
	}
	// Removing every device and adding one back keeps Run running.
	added, err := a.Apply(a.Tunnels(), specs(unreachableDevice("c.three")))
	if err != nil || len(added) != 1 {
		t.Fatalf("Apply = %v, %v", added, err)
	}
	select {
	case err := <-ran:
		t.Fatalf("Run returned during Apply: %v", err)
	default:
	}
	if got := identities(a); len(got) != 1 || got[0] != "c.three" {
		t.Fatalf("tunnels = %v, want [c.three]", got)
	}
	cancel()
	select {
	case <-ran:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if _, err := a.Apply(nil, nil); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Apply after Run = %v, want ErrNotRunning", err)
	}
}

func specs(s ...config.DeviceSpec) func() []config.DeviceSpec {
	return func() []config.DeviceSpec { return s }
}

// deviceOptions carries the spec into the tunnel: the identity (which keys
// session recordings and UI events), name, edge, host and session settings.
func TestDeviceOptionsCarryTheSpec(t *testing.T) {
	fda := tunnel.NewFullDiskAccessState()
	fda.Set("granted")
	spec := config.DeviceSpec{
		Name: "gw-01", Identity: "tun12345.gw-01", Host: "10.0.0.5", Edge: "eu.edge.localport.dev:443",
		Capabilities: []string{"terminal"}, Logins: []string{"pi"}, Desktop: []string{"vnc"},
		SessionAuth: "pam", RunAsAgent: true, FullDiskAccess: fda,
	}
	opts := deviceOptions(spec)
	if opts.Identity != spec.Identity || opts.Label != spec.Name || opts.ClientName != spec.Name || opts.Host != spec.Host || opts.Edge != spec.Edge {
		t.Fatalf("options identity=%q label=%q client=%q host=%q edge=%q", opts.Identity, opts.Label, opts.ClientName, opts.Host, opts.Edge)
	}
	if len(opts.Capabilities) != 1 || len(opts.Logins) != 1 || len(opts.Desktop) != 1 || opts.SessionAuth != "pam" || !opts.RunAsAgent || opts.FullDiskAccess.Load() != "granted" {
		t.Fatalf("session settings not carried: %+v", opts)
	}
	if opts.Credential != nil {
		t.Fatal("a spec without a registrar must leave the credential interface nil")
	}
}

// With KeepIdle, Run starts with no device, keeps running when its only
// device is removed, and returns nil once ctx ends.
func TestKeepIdleRunsWithoutDevicesUntilCancel(t *testing.T) {
	a := New(&config.Config{})
	a.KeepIdle = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := make(chan error, 1)
	go func() { ran <- a.Run(ctx, nil) }()
	<-a.Started()
	if _, err := a.Apply(nil, specs(unreachableDevice("a.one"))); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(a.Tunnels(), specs()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-ran:
		t.Fatalf("Run returned with no device left: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-ran:
		if err != nil {
			t.Fatalf("Run = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

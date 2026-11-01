package cli

import (
	"context"
	"testing"
	"time"

	"github.com/localport/agent/internal/agent"
	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/identity"
)

// set as root reloads the installed device service; it never restarts it.
func TestSetReloadsTheDeviceService(t *testing.T) {
	m := &fakeManager{installed: true}
	file := asRoot(t, m)
	writeDevices(t, file)
	if err := runSet([]string{"factory.gw-01", "--allow-ports", "80"}); err != nil {
		t.Fatalf("set = %v", err)
	}
	if m.reloads != 1 {
		t.Fatalf("reloads = %d, want 1", m.reloads)
	}
}

// A reload stops the tunnels of a changed and of a removed device and leaves
// the unchanged device's tunnel running. The changed device has no stored
// credential here, so its rebuild is skipped.
func TestReloadAppliesOnlyChangedDevices(t *testing.T) {
	unchanged, changed, removed := deviceRef("factory.keep"), deviceRef("factory.edit"), deviceRef("factory.gone")
	spec := func(ref identity.Ref) config.DeviceSpec {
		return config.DeviceSpec{Name: ref.Identity, Identity: ref.Identity, Edge: "127.0.0.1:1", Host: "127.0.0.1"}
	}
	a := agent.New(&config.Config{Devices: []config.DeviceSpec{spec(unchanged), spec(changed), spec(removed)}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := make(chan error, 1)
	go func() { ran <- a.Run(ctx, nil) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(a.Tunnels()) < 3 {
		if time.Now().After(deadline) {
			t.Fatal("the devices did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	keep := deviceTunnel(a.Tunnels(), unchanged.Identity)

	store := &identity.Store{Root: t.TempDir()}
	r := &deviceRunner{parent: ctx, store: store, logEvent: func(string) {}, probed: true, served: map[identity.Ref]*servedDevice{}}
	for _, ref := range []identity.Ref{unchanged, changed, removed} {
		r.served[ref] = &servedDevice{local: config.LocalDevice{Identity: ref}}
	}
	edited := config.LocalDevice{Identity: changed}
	edited.Host = "10.0.0.2"
	r.reload(ctx, a, []config.LocalDevice{{Identity: unchanged}, edited})

	got := a.Tunnels()
	if len(got) != 1 || got[0] != keep {
		t.Fatalf("tunnels after reload = %d, want only the unchanged device's", len(got))
	}
	if _, ok := r.served[unchanged]; !ok || len(r.served) != 1 {
		t.Fatalf("served after reload = %v, want only the unchanged device", r.served)
	}
	if !r.isConfigured(changed.Identity) || r.isConfigured(removed.Identity) {
		t.Fatal("the uploader's device list was not replaced")
	}
	cancel()
	<-ran
}

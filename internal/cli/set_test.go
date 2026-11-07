package cli

import (
	"context"
	"errors"
	"os"
	"runtime"
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
	r := &deviceRunner{parent: ctx, store: store, logEvent: func(string) {}, probed: true, noMux: true, served: map[identity.Ref]*servedDevice{}}
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

// A reload probes the launcher again for the devices it starts; with noMux
// nothing is probed.
func TestReloadProbesTheLauncherAgain(t *testing.T) {
	for _, noMux := range []bool{false, true} {
		r := &deviceRunner{logEvent: func(string) {}, probed: true, noMux: noMux, served: map[identity.Ref]*servedDevice{}}
		r.reload(context.Background(), nil, nil)
		if r.probed != noMux {
			t.Errorf("noMux %v: probed = %v after reload, want %v", noMux, r.probed, noMux)
		}
	}
}

// --vnc-reset-pin alone forgets the device's VNC server key without writing
// the config or reloading; with another flag it does both; a second reset
// finds none.
func TestSetResetsTheVNCKeyPin(t *testing.T) {
	m := &fakeManager{installed: true}
	file := asRoot(t, m)
	writeDevices(t, file)
	store, err := identity.SystemStore(file.Base)
	if err != nil {
		t.Fatal(err)
	}
	ref := deviceRef("factory.gw-01")
	pins, err := store.DesktopPins(ref)
	if err != nil {
		t.Fatal(err)
	}
	pin := func() {
		t.Helper()
		if _, err := pins.Pin(context.Background(), "vnc", "127.0.0.1:5900", [32]byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	held := func() bool {
		t.Helper()
		_, ok, err := pins.Lookup("vnc", "127.0.0.1:5900")
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	pin()
	before, err := os.ReadFile(file.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := runSet([]string{"factory.gw-01", "--vnc-reset-pin"}); err != nil {
		t.Fatalf("set --vnc-reset-pin = %v", err)
	}
	if held() {
		t.Fatal("the pin survived the reset")
	}
	if after, _ := os.ReadFile(file.Path); string(after) != string(before) || m.reloads != 0 {
		t.Fatalf("a reset alone wrote the config (%v) or reloaded (%d)", string(after) != string(before), m.reloads)
	}
	if err := runSet([]string{"factory.gw-01", "--vnc-reset-pin"}); err != nil {
		t.Fatalf("second reset = %v", err)
	}
	pin()
	if err := runSet([]string{"factory.gw-01", "--allow-ports", "80", "--vnc-reset-pin"}); err != nil {
		t.Fatalf("set with a setting and the reset = %v", err)
	}
	if held() || m.reloads != 1 {
		t.Fatalf("pin held %v, reloads %d; want reset and one reload", held(), m.reloads)
	}
	if runtime.GOOS == "windows" {
		return
	}
	// A reset that fails still leaves the saved setting applied.
	dir := store.Dir(ref)
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	err = runSet([]string{"factory.gw-01", "--allow-ports", "81", "--vnc-reset-pin"})
	if !errors.Is(err, identity.ErrDesktopPinsUnreadable) || m.reloads != 2 {
		t.Fatalf("set with a failing reset = %v, reloads %d; want the pin error and a second reload", err, m.reloads)
	}
}

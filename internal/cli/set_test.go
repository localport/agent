package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/localport/agent/internal/agent"
	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/security"
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

// desktopPinTargets are the targets the reset tests pin, by kind.
var desktopPinTargets = map[string]string{"rdp": "127.0.0.1:3389", "vnc": "127.0.0.1:5900"}

// The set-pins child forgets the named kind's key in the system store and
// keeps the other kind's; a bad ref or kind is refused.
func TestSetPinsChildResetsThePin(t *testing.T) {
	file := asRoot(t, &fakeManager{installed: true})
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
	for _, kind := range []string{"rdp", "vnc"} {
		if _, err := pins.Pin(context.Background(), kind, desktopPinTargets[kind], [32]byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	if err := runSetPinsChild([]string{ref.String(), "rdp"}); err != nil {
		t.Fatalf("set-pins = %v", err)
	}
	_, rdp, err := pins.Lookup("rdp", desktopPinTargets["rdp"])
	if err != nil {
		t.Fatal(err)
	}
	_, vnc, err := pins.Lookup("vnc", desktopPinTargets["vnc"])
	if err != nil {
		t.Fatal(err)
	}
	if rdp || !vnc {
		t.Fatalf("after set-pins rdp held %v, vnc held %v; want only rdp forgotten", rdp, vnc)
	}
	for _, args := range [][]string{{ref.String()}, {"factory.gw-01", "rdp"}, {ref.String(), "ssh"}} {
		if err := runSetPinsChild(args); !errors.Is(err, errcode.New(errcode.AgentChildOnly)) {
			t.Errorf("set-pins %q = %v, want AgentChildOnly", args, err)
		}
	}
}

// Root on the system layout never opens the store: a pin reset runs in the
// set-pins agent child. A reset after a setting takes the same resetPins
// path; writing the system config here would need the agent group.
func TestSetRootResetsPinsInTheAgentChild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the agent child runs under Unix root only (agentChildRoot)")
	}
	file := asRoot(t, &fakeManager{installed: true})
	writeDevices(t, file)
	file.System = true
	t.Cleanup(security.OverrideSystemOwner(os.Getuid()))
	restoreRoot, restoreRun := agentChildRoot, runPinsChild
	t.Cleanup(func() { agentChildRoot, runPinsChild = restoreRoot, restoreRun })
	systemLocalConfig = func() (config.LocalConfigFile, error) { return file, nil }
	agentChildRoot = func() bool { return true }
	var calls [][]string
	runPinsChild = func(args []string, _ io.Reader, _ io.Writer) error {
		calls = append(calls, args)
		return nil
	}
	ref := deviceRef("factory.gw-01").String()
	for _, args := range [][]string{
		{"factory.gw-01", "--rdp-reset-pin", "--vnc-reset-pin"},
		{"factory.gw-01", "--vnc-reset-pin"},
	} {
		if err := runSet(args); err != nil {
			t.Fatalf("set %q = %v", args, err)
		}
	}
	want := [][]string{{"set-pins", ref, "rdp", "vnc"}, {"set-pins", ref, "vnc"}}
	if !slices.EqualFunc(calls, want, slices.Equal) {
		t.Fatalf("children = %q, want %q", calls, want)
	}
}

// --rdp-reset-pin and --vnc-reset-pin alone forget the device's key of their
// kind, and only that kind's, without writing the config or reloading; with
// another flag they do both; a second reset finds none.
func TestSetResetsTheDesktopKeyPin(t *testing.T) {
	for kind, other := range map[string]string{"rdp": "vnc", "vnc": "rdp"} {
		t.Run(kind, func(t *testing.T) {
			flag := "--" + kind + "-reset-pin"
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
			pin := func(kind string) {
				t.Helper()
				if _, err := pins.Pin(context.Background(), kind, desktopPinTargets[kind], [32]byte{1}); err != nil {
					t.Fatal(err)
				}
			}
			held := func(kind string) bool {
				t.Helper()
				_, ok, err := pins.Lookup(kind, desktopPinTargets[kind])
				if err != nil {
					t.Fatal(err)
				}
				return ok
			}
			pin(kind)
			pin(other)
			before, err := os.ReadFile(file.Path)
			if err != nil {
				t.Fatal(err)
			}
			if err := runSet([]string{"factory.gw-01", flag}); err != nil {
				t.Fatalf("set %s = %v", flag, err)
			}
			if held(kind) || !held(other) {
				t.Fatalf("after the reset %s held %v, %s held %v; want only %s forgotten", kind, held(kind), other, held(other), kind)
			}
			if after, _ := os.ReadFile(file.Path); string(after) != string(before) || m.reloads != 0 {
				t.Fatalf("a reset alone wrote the config (%v) or reloaded (%d)", string(after) != string(before), m.reloads)
			}
			if err := runSet([]string{"factory.gw-01", flag}); err != nil {
				t.Fatalf("second reset = %v", err)
			}
			pin(kind)
			if err := runSet([]string{"factory.gw-01", "--allow-ports", "80", flag}); err != nil {
				t.Fatalf("set with a setting and the reset = %v", err)
			}
			if held(kind) || m.reloads != 1 {
				t.Fatalf("pin held %v, reloads %d; want reset and one reload", held(kind), m.reloads)
			}
			pin(kind)
			if err := runSet([]string{"factory.gw-01", "--rdp-reset-pin", "--vnc-reset-pin"}); err != nil {
				t.Fatalf("both resets = %v", err)
			}
			if held("rdp") || held("vnc") || m.reloads != 1 {
				t.Fatalf("both resets: rdp held %v, vnc held %v, reloads %d", held("rdp"), held("vnc"), m.reloads)
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
			err = runSet([]string{"factory.gw-01", "--allow-ports", "81", flag})
			if !errors.Is(err, identity.ErrDesktopPinsUnreadable) || m.reloads != 2 {
				t.Fatalf("set with a failing reset = %v, reloads %d; want the pin error and a second reload", err, m.reloads)
			}
		})
	}
}

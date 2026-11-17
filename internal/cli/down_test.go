package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/security"
	"github.com/localport/agent/internal/service"
	"github.com/localport/agent/internal/status"
)

var (
	gw01 = deviceRef("factory.gw-01")
	gw02 = deviceRef("factory.gw-02")
)

// pauseFixture is root with a running device service and two enrolled
// devices; the status endpoint reports each device as its config says.
func pauseFixture(t *testing.T) (config.LocalConfigFile, *fakeManager) {
	t.Helper()
	m := &fakeManager{installed: true, mainPID: 1}
	file := asRoot(t, m)
	if err := config.WriteLocal(file, &config.LocalConfig{Devices: []config.LocalDevice{{Identity: gw01}, {Identity: gw02}}}, identity.Ref{}); err != nil {
		t.Fatal(err)
	}
	prev := readDocument
	t.Cleanup(func() { readDocument = prev })
	readDocument = func(context.Context) (*status.Document, error) {
		local, err := config.LoadLocal(file)
		if err != nil {
			return nil, err
		}
		doc := &status.Document{Version: status.Version}
		for _, d := range local.Devices {
			state := status.StateRunning
			if d.Paused {
				state = status.StatePaused
			}
			doc.Devices = append(doc.Devices, status.Device{Identity: d.Identity.Identity, State: state})
		}
		return doc, nil
	}
	return file, m
}

func pausedOf(t *testing.T, file config.LocalConfigFile) map[identity.Ref]bool {
	t.Helper()
	local, err := config.LoadLocal(file)
	if err != nil {
		t.Fatal(err)
	}
	out := map[identity.Ref]bool{}
	for _, d := range local.Devices {
		out[d.Identity] = d.Paused
	}
	return out
}

// down pauses the named device only and reloads the service; a second down
// changes nothing and reloads nothing; up resumes it and reloads.
func TestDownAndUpRoundTrip(t *testing.T) {
	file, m := pauseFixture(t)
	if err := runDown([]string{"gw-01"}); err != nil {
		t.Fatal(err)
	}
	if got := pausedOf(t, file); !got[gw01] || got[gw02] || m.reloads != 1 {
		t.Fatalf("after down: paused %v, reloads %d; want gw-01 only and 1", got, m.reloads)
	}
	if err := runDown([]string{"gw-01"}); err != nil || m.reloads != 1 {
		t.Fatalf("down of a paused device = %v, reloads %d; want nil and no reload", err, m.reloads)
	}
	if err := runUp("test", []string{"factory.gw-01"}); err != nil {
		t.Fatal(err)
	}
	if got := pausedOf(t, file); got[gw01] || m.reloads != 2 {
		t.Fatalf("after up: paused %v, reloads %d; want none and 2", got, m.reloads)
	}
	if err := runDown([]string{"--all"}); err != nil {
		t.Fatal(err)
	}
	if got := pausedOf(t, file); !got[gw01] || !got[gw02] {
		t.Fatalf("after down --all: paused %v, want both", got)
	}
}

// up with no entry to change still reloads the service (a parked device is
// retried); with the service stopped, up starts it and down leaves it stopped.
func TestPauseAppliesToTheService(t *testing.T) {
	file, m := pauseFixture(t)
	if err := runUp("test", []string{"gw-01"}); err != nil || m.reloads != 1 {
		t.Fatalf("up of a running device = %v, reloads %d; want nil and 1", err, m.reloads)
	}
	m.mainPID = 0
	if err := runDown([]string{"gw-01"}); err != nil || m.restarts != 0 || m.reloads != 1 {
		t.Fatalf("down with the service stopped = %v, restarts %d, reloads %d; want no start and no reload", err, m.restarts, m.reloads)
	}
	if !pausedOf(t, file)[gw01] {
		t.Fatal("down with the service stopped did not write paused")
	}
	if err := runUp("test", []string{"gw-01"}); err != nil || m.restarts != 1 {
		t.Fatalf("up with the service stopped = %v, restarts %d; want the service started", err, m.restarts)
	}
}

// The store facts are read under the same config lock as the write, so a
// concurrent `up <join-token>` cannot be pruned by a stale read.
func TestDeviceFactsAreReadUnderTheConfigLock(t *testing.T) {
	file, _ := pauseFixture(t)
	prev := readFacts
	t.Cleanup(func() { readFacts = prev })
	var held bool
	readFacts = func(f config.LocalConfigFile, who invoker, devices []config.LocalDevice) (map[identity.Ref]deviceFact, error) {
		lock, err := security.OpenLockFile(f.LockPath())
		if err != nil {
			return nil, err
		}
		defer lock.Close()
		got, err := security.TryLockFile(lock)
		if got {
			_ = security.UnlockFile(lock)
		}
		held = err == nil && !got
		return prev(f, who, devices)
	}
	if err := runDown([]string{"gw-01"}); err != nil {
		t.Fatal(err)
	}
	if !held {
		t.Fatalf("the store facts of %s were read without the config lock held", file.Path)
	}
}

// up and down change the machine-wide config: anyone but root is refused
// before anything is read or written.
func TestPauseNeedsRoot(t *testing.T) {
	file, m := pauseFixture(t)
	asUnprivileged(t)
	for _, run := range []func() error{
		func() error { return runDown([]string{"gw-01"}) },
		func() error { return runUp("test", []string{"gw-01"}) },
	} {
		if err := run(); !errors.Is(err, config.ErrSystemNotRoot) || !strings.Contains(err.Error(), "sudo localport") {
			t.Fatalf("unprivileged = %v, want %s naming sudo", err, errcode.SystemNeedsRoot)
		}
	}
	if got := pausedOf(t, file); got[gw01] || m.reloads != 0 {
		t.Fatalf("a refused command changed the config (%v) or reloaded (%d)", got, m.reloads)
	}
}

// A device the store forgot (a tombstone and no credential) leaves the
// config with the next write.
func TestPausePrunesRemovedDevices(t *testing.T) {
	file, _ := pauseFixture(t)
	store, err := currentInvoker(false).store()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureRoot(); err != nil {
		t.Fatal(err)
	}
	// The team directory a forgotten credential leaves behind.
	if err := os.MkdirAll(filepath.Dir(store.Dir(gw02)), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Forget(context.Background(), gw02, identity.CodeDeviceUnknown, ""); err != nil {
		t.Fatal(err)
	}
	if err := runDown([]string{"gw-01"}); err != nil {
		t.Fatal(err)
	}
	if got := pausedOf(t, file); len(got) != 1 || !got[gw01] {
		t.Fatalf("config after down = %v, want gw-01 alone, paused", got)
	}
}

func TestSelectDevices(t *testing.T) {
	devices := []config.LocalDevice{{Identity: gw01}, {Identity: gw02}}
	prev := pickerTTY
	t.Cleanup(func() { pickerTTY = prev })
	pickerTTY = func() bool { return false }

	if idx, err := selectDevices(devices[:1], nil, "", false, "localport down"); err != nil || len(idx) != 1 {
		t.Fatalf("one device = %v, %v; want it", idx, err)
	}
	for _, sel := range []string{"gw-02", "factory.gw-02", gw02.String(), gw02.Team + "/gw-02"} {
		if idx, err := selectDevices(devices, nil, sel, false, "localport down"); err != nil || len(idx) != 1 || idx[0] != 1 {
			t.Errorf("selector %q = %v, %v; want gw-02", sel, idx, err)
		}
	}
	if _, err := selectDevices(devices, nil, "gw-09", false, "localport down"); !errors.Is(err, errcode.New(errcode.DeviceNotFound)) {
		t.Errorf("unknown selector = %v, want %s", err, errcode.DeviceNotFound)
	}
	if idx, err := selectDevices(devices, nil, "", true, "localport down"); err != nil || len(idx) != 2 {
		t.Errorf("--all = %v, %v; want both", idx, err)
	}
	_, err := selectDevices(devices, nil, "", false, "localport down")
	if !errors.Is(err, errcode.New(errcode.DeviceAmbiguous)) || !strings.Contains(err.Error(), "sudo localport down "+gw01.String()) ||
		!strings.Contains(err.Error(), "sudo localport down --all") {
		t.Errorf("several without a terminal = %v, want each exact command", err)
	}
}

func TestChooseDevices(t *testing.T) {
	devices := []config.LocalDevice{{Identity: gw01}, {Identity: gw02, Host: "192.168.1.9", Paused: true}}
	facts := map[identity.Ref]deviceFact{gw02: {Host: "gw-02-factory.eu.localport.dev", Team: "Factory"}}
	var out bytes.Buffer
	idx, err := chooseDevices(strings.NewReader("9\n2\n"), &out, devices, facts)
	if err != nil || len(idx) != 1 || idx[0] != 1 {
		t.Fatalf("choice = %v, %v; want gw-02", idx, err)
	}
	for _, want := range []string{"gw-02-factory.eu.localport.dev", "192.168.1.9", "this machine", "Factory (" + gw02.Team + ")", "paused", "a)", "Enter a number"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("prompt lacks %q:\n%s", want, out.String())
		}
	}
	if idx, err := chooseDevices(strings.NewReader("a\n"), io.Discard, devices, facts); err != nil || len(idx) != 2 {
		t.Fatalf("a = %v, %v; want both", idx, err)
	}
	if _, err := chooseDevices(strings.NewReader(""), io.Discard, devices, facts); err == nil {
		t.Fatal("EOF chose a device")
	}
}

// Root reads the store through the devices child and trusts nothing it
// prints: unknown fields, another version, an invalid removal code and output
// past the cap are refused; refs outside root's config are ignored; strings
// are sanitized.
func TestDeviceFactsFromTheChild(t *testing.T) {
	prevRoot, prevChild := agentChildRoot, runDevicesStorePart
	t.Cleanup(func() { agentChildRoot, runDevicesStorePart = prevRoot, prevChild })
	agentChildRoot = func() bool { return true }
	file := config.LocalConfigFile{System: true}
	child := func(out string) {
		runDevicesStorePart = func(args []string, _ io.Reader, w io.Writer) error {
			if len(args) != 1 || args[0] != "devices" {
				t.Fatalf("child args = %q", args)
			}
			_, err := io.WriteString(w, out)
			return err
		}
	}
	line := func(ref identity.Ref, extra string) string {
		return fmt.Sprintf(`{"version":1,"ref":%q,"host":"h\u001b[31m","team":"T"%s}`+"\n", ref.String(), extra)
	}

	child(line(gw01, `,"removed":"SE018"`) + line(gw02, ""))
	facts, err := readDeviceFacts(file, invoker{}, []config.LocalDevice{{Identity: gw01}})
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 1 || facts[gw01].Removed != "SE018" || strings.ContainsRune(facts[gw01].Host, 0x1b) {
		t.Fatalf("facts = %+v, want gw-01 only, sanitized", facts)
	}
	for name, out := range map[string]string{
		"unknown field":   line(gw01, `,"key":"x"`),
		"another version": strings.Replace(line(gw01, ""), `"version":1`, `"version":2`, 1),
		"removal code":    line(gw01, `,"removed":"SE031"`),
		"over the cap":    strings.Repeat(line(gw01, ""), maxDeviceFacts/len(line(gw01, ""))+1),
	} {
		child(out)
		if _, err := readDeviceFacts(file, invoker{}, []config.LocalDevice{{Identity: gw01}}); !errors.Is(err, errcode.New(errcode.AgentChildFailed)) {
			t.Errorf("%s: readDeviceFacts = %v, want %s", name, err, errcode.AgentChildFailed)
		}
	}
}

func TestResumesDevices(t *testing.T) {
	for args, want := range map[string]bool{
		"":                  true,
		"gw-01":             true,
		"--all":             true,
		"lpj_x":             false,
		"--config x.yaml":   false,
		"gw-01 --enable x":  false,
		"--foreground":      false,
		"lpj_x --logins pi": false,
	} {
		if got := resumesDevices(strings.Fields(args)); got != want {
			t.Errorf("resumesDevices(%q) = %v, want %v", args, got, want)
		}
	}
}

// Each state reads as its row and remedy.
func TestDescribeRow(t *testing.T) {
	for state, want := range map[string]string{
		status.StateRunning:      "running",
		status.StatePaused:       "sudo localport up",
		status.StateDisconnected: "disconnected by an admin",
		status.StateDraining:     "ending its sessions",
		status.StateWaiting:      "waiting: refused with BL011",
		status.StateParked:       "stopped: refused with BL011",
		status.StateRemoved:      "up <join-token>",
	} {
		if got := describeRow(&status.Device{State: state, Code: "BL011"}); !strings.Contains(got, want) {
			t.Errorf("%s = %q, want it to contain %q", state, got, want)
		}
	}
}

// The account line says ok, missing or unsafe.
func TestStatusAccountLine(t *testing.T) {
	prev := checkAccount
	t.Cleanup(func() { checkAccount = prev })
	for want, err := range map[string]error{
		"ok":    nil,
		"AG137": errcode.New(errcode.AccountMissing).With(nil, ""),
		"AG147": errcode.New(errcode.AgentAccountUnsafe).With(nil, "shell /bin/zsh"),
	} {
		checkAccount = func(context.Context) (service.Account, error) { return service.Account{UID: 450}, err }
		var out bytes.Buffer
		printAccount(context.Background(), &out)
		if !strings.Contains(out.String(), want) {
			t.Errorf("account line %q, want %q", out.String(), want)
		}
	}
}

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/launcher"
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

// configLockHeld reports whether a process holds f's config lock (LockLocal):
// it opens the lock (the directory on Linux and macOS, the file on Windows)
// and tries it, releasing it at once when free.
func configLockHeld(f config.LocalConfigFile) (bool, error) {
	lock, err := os.Open(f.LockPath())
	if err != nil {
		return false, err
	}
	defer lock.Close()
	free, err := security.TryLockFile(lock)
	if free {
		_ = security.UnlockFile(lock)
	}
	return err == nil && !free, err
}

// The store facts are read under the same config lock as the write, so a
// concurrent `up <join-token>` cannot be pruned by a stale read.
func TestDeviceFactsAreReadUnderTheConfigLock(t *testing.T) {
	file, _ := pauseFixture(t)
	prev := readFacts
	t.Cleanup(func() { readFacts = prev })
	var held bool
	readFacts = func(f config.LocalConfigFile, who invoker, devices []config.LocalDevice) (map[identity.Ref]deviceFact, error) {
		var err error
		if held, err = configLockHeld(f); err != nil {
			return nil, err
		}
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

	if idx, err := selectDevices(devices[:1], "", false, "down"); err != nil || len(idx) != 1 {
		t.Fatalf("one device = %v, %v; want it", idx, err)
	}
	for _, sel := range []string{"gw-02", "factory.gw-02", gw02.String(), gw02.Team + "/gw-02"} {
		if idx, err := selectDevices(devices, sel, false, "down"); err != nil || len(idx) != 1 || idx[0] != 1 {
			t.Errorf("selector %q = %v, %v; want gw-02", sel, idx, err)
		}
	}
	if _, err := selectDevices(devices, "gw-09", false, "down"); !errors.Is(err, errcode.New(errcode.DeviceNotFound)) {
		t.Errorf("unknown selector = %v, want %s", err, errcode.DeviceNotFound)
	}
	if idx, err := selectDevices(devices, "", true, "down"); err != nil || len(idx) != 2 {
		t.Errorf("--all = %v, %v; want both", idx, err)
	}
	prefix := "sudo localport down "
	if runtime.GOOS == "windows" {
		prefix = "localport down "
	}
	_, err := selectDevices(devices, "", false, "down")
	if !errors.Is(err, errcode.New(errcode.DeviceNotNamed)) || !strings.Contains(err.Error(), prefix+gw01.String()) ||
		!strings.Contains(err.Error(), prefix+"--all") {
		t.Errorf("several without a terminal = %v, want each exact command", err)
	}
	if _, err := selectDevices(nil, "", false, "down"); !errors.Is(err, errNoDevice) {
		t.Errorf("no device = %v, want %v", err, errNoDevice)
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
// prints: unknown fields, another version, an invalid removal code, data after
// the object and output past the cap are refused; refs outside root's config
// are ignored; strings are sanitized.
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
		"trailing data":   strings.TrimSuffix(line(gw01, ""), "\n") + ` {"version":1}` + "\n",
	} {
		child(out)
		if _, err := readDeviceFacts(file, invoker{}, []config.LocalDevice{{Identity: gw01}}); !errors.Is(err, errcode.New(errcode.AgentChildOutput)) {
			t.Errorf("%s: readDeviceFacts = %v, want %s", name, err, errcode.AgentChildOutput)
		}
	}

	// A failed child has printed its own error; its AG037 is returned as is.
	failed := errcode.New(errcode.AgentChildFailed).With(nil, "localport devices")
	runDevicesStorePart = func([]string, io.Reader, io.Writer) error { return failed }
	if _, err := readDeviceFacts(file, invoker{}, []config.LocalDevice{{Identity: gw01}}); err != failed {
		t.Errorf("failed child: readDeviceFacts = %v, want %v unwrapped", err, failed)
	}
}

func TestResumesDevices(t *testing.T) {
	for args, want := range map[string]bool{
		"":                  true,
		"gw-01":             true,
		"--all":             true,
		"-all":              true,
		"--all=true":        true,
		"--allow-ports 22":  false,
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
		status.StateConnecting:   "connecting",
		status.StatePaused:       "localport up",
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
	if got := describeRow(nil); !strings.Contains(got, "not reported") {
		t.Errorf("no row = %q, want it not reported", got)
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
		"ok except the password, which only root can check": service.ErrPasswordUnchecked,
	} {
		checkAccount = func(context.Context) (service.Account, error) { return service.Account{UID: 450}, err }
		var out bytes.Buffer
		printAccount(context.Background(), &out)
		if !strings.Contains(out.String(), want) {
			t.Errorf("account line %q, want %q", out.String(), want)
		}
	}
}

// For up a device settles once it leaves connecting and paused, and a parked
// one only once it parked again after up's retry; for down a device settles
// once paused.
func TestStatesSettled(t *testing.T) {
	applied := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	before, after := applied.Add(-time.Hour), applied.Add(time.Second)
	for _, c := range []struct {
		name  string
		pause bool
		row   *status.Device
		want  bool
	}{
		{"up: no row", false, nil, false},
		{"up: connecting", false, &status.Device{State: status.StateConnecting, Since: after}, false},
		{"up: still paused", false, &status.Device{State: status.StatePaused, Since: before}, false},
		{"up: running", false, &status.Device{State: status.StateRunning, Since: before}, true},
		{"up: disconnected by an admin before", false, &status.Device{State: status.StateDisconnected, Since: before}, true},
		{"up: waiting before", false, &status.Device{State: status.StateWaiting, Since: before}, true},
		{"up: parked before the retry", false, &status.Device{State: status.StateParked, Since: before}, false},
		{"up: parked after the retry", false, &status.Device{State: status.StateParked, Since: after}, true},
		{"down: running", true, &status.Device{State: status.StateRunning, Since: after}, false},
		{"down: paused", true, &status.Device{State: status.StatePaused, Since: after}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			doc := &status.Document{Version: status.Version}
			if c.row != nil {
				row := *c.row
				row.Identity = gw01.Identity
				doc.Devices = append(doc.Devices, row)
			}
			if got := statesSettled(doc, []identity.Ref{gw01}, c.pause, applied); got != c.want {
				t.Fatalf("statesSettled = %v, want %v", got, c.want)
			}
		})
	}
}

// A device name beside an enrolment flag is refused locally, never sent to
// the control plane as a join token.
func TestUpRefusesADeviceNameAsAJoinToken(t *testing.T) {
	t.Setenv(identity.HomeEnv, t.TempDir())
	asUnprivileged(t)
	calls := fakeEnrol(t, gw01)
	for _, args := range [][]string{{"gw-01", "--foreground"}, {"--enable", "terminal", "gw-01"}} {
		if err := runUp("test", args); !errors.Is(err, errNotJoinToken) {
			t.Errorf("up %q = %v, want %v", args, err, errNotJoinToken)
		}
	}
	if *calls != 0 {
		t.Fatalf("the control plane was called %d times", *calls)
	}
}

// The devices child's output for a full config of the longest facts fits its
// cap and decodes.
func TestFullDeviceFactsFitTheCap(t *testing.T) {
	facts := make([]deviceFact, config.MaxDevices)
	for i := range facts {
		ref := identity.Ref{Team: strings.Repeat("t", 64), Kind: identity.KindDevice,
			Identity: fmt.Sprintf("%03d%s.%s", i, strings.Repeat("a", 61), strings.Repeat("p", 64))}
		facts[i] = deviceFact{Version: deviceFactsVersion, Ref: ref.String(), Host: strings.Repeat("h", maxHostName),
			Team: strings.Repeat(`"`, maxTeamDisplay), Removed: "SE041"}
	}
	var out cappedBuffer
	out.max = maxDeviceFacts
	if err := writeDeviceFacts(&out, facts); err != nil {
		t.Fatalf("writeDeviceFacts = %v; %d facts of the longest strings must fit %d bytes", err, len(facts), maxDeviceFacts)
	}
	if got, err := decodeDeviceFacts(out.Bytes()); err != nil || len(got) != len(facts) {
		t.Fatalf("decodeDeviceFacts = %d facts, %v", len(got), err)
	}
}

func TestTruncateDisplay(t *testing.T) {
	for _, c := range []struct {
		in   string
		n    int
		want string
	}{
		{"Factory", 128, "Factory"},
		{"abcdef", 5, "ab…"},
		{"aé€x", 7, "aé€x"},
		{"aé€x", 6, "aé…"},
		{"aé€x", 5, "a…"},
	} {
		if got := truncateDisplay(c.in, c.n); got != c.want || len(got) > c.n {
			t.Errorf("truncateDisplay(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

// up refuses before the spend when the config is full, unless a removed
// device's entry would be pruned.
func TestUpRefusesAFullConfigBeforeTheSpend(t *testing.T) {
	t.Setenv(identity.HomeEnv, t.TempDir())
	asUnprivileged(t)
	calls := fakeEnrol(t, gw01)
	file, err := currentInvoker(false).localConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	local := &config.LocalConfig{}
	for i := range config.MaxDevices {
		local.Devices = append(local.Devices, config.LocalDevice{Identity: deviceRef(fmt.Sprintf("factory.gw-%02d", i))})
	}
	if err := config.WriteLocal(file, local, identity.Ref{}); err != nil {
		t.Fatal(err)
	}
	if err := runUp("test", upArgs); !errors.Is(err, errcode.New(errcode.DeviceLimit)) {
		t.Fatalf("up on a full config = %v, want %s", err, errcode.DeviceLimit)
	}
	if *calls != 0 {
		t.Fatalf("the join token was spent %d times", *calls)
	}
	prev := readFacts
	t.Cleanup(func() { readFacts = prev })
	removed := local.Devices[0].Identity
	reads := 0
	readFacts = func(config.LocalConfigFile, invoker, []config.LocalDevice) (map[identity.Ref]deviceFact, error) {
		reads++
		return map[identity.Ref]deviceFact{removed: {Ref: removed.String(), Removed: "SE018"}}, nil
	}
	if _, err := refuseFullConfig(file, currentInvoker(false)); err != nil {
		t.Fatalf("a full config with a removed device = %v, want room", err)
	}
	// up spends the token and records the device with the facts the check
	// read under the same lock hold: the removed entry goes, none are read again.
	reads = 0
	prevServe := serveEnrolled
	t.Cleanup(func() { serveEnrolled = prevServe })
	serveEnrolled = func(context.Context, string, *identity.Store, []config.LocalDevice, bool, bool, func() ([]config.LocalDevice, error)) error {
		return nil
	}
	if err := runUp("test", upArgs); err != nil {
		t.Fatalf("up on a full config with a removed device = %v", err)
	}
	after, err := config.LoadLocal(file)
	if err != nil {
		t.Fatal(err)
	}
	if reads != 1 || *calls != 1 || len(after.Devices) != config.MaxDevices-1 ||
		slices.ContainsFunc(after.Devices, func(d config.LocalDevice) bool { return d.Identity == removed }) {
		t.Fatalf("facts read %d times, enrolments %d, %d entries; want 1, 1 and %d without %s", reads, *calls, len(after.Devices), config.MaxDevices-1, removed)
	}
}

// With a foreground run serving the devices, up and down ask it to reload
// and never start or reload the installed service, which would wait on the
// run's run.lock.
func TestUpAndDownReachAForegroundRunFirst(t *testing.T) {
	_, m := pauseFixture(t)
	m.mainPID = 0
	asked := 0
	requestReload = func(context.Context) error { asked++; return nil }
	if err := runDown([]string{"gw-01"}); err != nil {
		t.Fatal(err)
	}
	if err := runUp("test", []string{"gw-01"}); err != nil {
		t.Fatal(err)
	}
	if asked != 2 || m.restarts != 0 || m.reloads != 0 {
		t.Fatalf("asked the foreground run %d times, service restarts %d, reloads %d; want 2, 0, 0", asked, m.restarts, m.reloads)
	}
}

// A foreground run that holds run.lock but is still starting (enrolling, or
// waiting for approval) gets the change when it starts: up and down neither
// start nor reload the stopped service beside it, and wait for no states.
func TestUpAndDownLeaveAStartingForegroundRunToApply(t *testing.T) {
	_, m := pauseFixture(t)
	m.mainPID = 0
	asked := 0
	requestReload = func(context.Context) error { asked++; return launcher.ErrRunStarting }
	readDocument = func(context.Context) (*status.Document, error) {
		t.Error("waited for the states of a run that is starting")
		return nil, launcher.ErrUnavailable
	}
	if err := runDown([]string{"gw-01"}); err != nil {
		t.Fatal(err)
	}
	if err := runUp("test", []string{"gw-01"}); err != nil {
		t.Fatal(err)
	}
	if asked != 2 || m.restarts != 0 || m.reloads != 0 {
		t.Fatalf("asked the starting run %d times, service restarts %d, reloads %d; want 2, 0, 0", asked, m.restarts, m.reloads)
	}
}

// A control request is answered that the run is starting, and queues nothing,
// until the devices' runner subscribes; after it, each request queues one
// coalesced reload.
func TestControlReloadsAnswerStartingUntilSubscribed(t *testing.T) {
	r := newControlReloads()
	if r.request() {
		t.Fatal("a request before the runner subscribed was queued")
	}
	sig, stop := r.subscribe()
	defer stop()
	if len(sig) != 0 {
		t.Fatal("a request before the runner subscribed left a reload signal")
	}
	for range 2 {
		if !r.request() {
			t.Fatal("a request after the subscription was answered as starting")
		}
	}
	if len(sig) != 1 {
		t.Fatalf("requests after the subscription: %d signals queued, want 1", len(sig))
	}
}

// The run.lock holder subscribes to reload requests before it reads the
// config: a foreground run stops answering `starting` and queues each later
// request, and the service catches SIGHUP, so no change saved after the read
// is lost. The config here fails to load, which ends the run at the read.
func TestHeldRunSubscribesBeforeItReadsTheConfig(t *testing.T) {
	file := asRoot(t, &fakeManager{})
	if err := os.MkdirAll(filepath.Dir(file.Path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file.Path, []byte("devices: [unclosed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newControlReloads()
	if err := serveHeldDevices(context.Background(), "test", currentInvoker(true), file, true, false, r.subscribe); err == nil {
		t.Fatal("serveHeldDevices loaded a malformed config")
	}
	if !r.request() {
		t.Fatal("the foreground run read the config before it queued requests")
	}

	prev := notifyReload
	t.Cleanup(func() { notifyReload = prev })
	serviceSubscribed := false
	notifyReload = func() (<-chan os.Signal, func()) {
		serviceSubscribed = true
		return make(chan os.Signal, 1), func() {}
	}
	if err := serveHeldDevices(context.Background(), "test", currentInvoker(true), file, true, false, nil); err == nil {
		t.Fatal("serveHeldDevices loaded a malformed config")
	}
	if !serviceSubscribed {
		t.Fatal("the service read the config before it subscribed to SIGHUP")
	}
}

// A control endpoint that refuses or is untrusted is AG116; the service is
// not touched.
func TestAForegroundRunThatDoesNotAnswerIsNotApplied(t *testing.T) {
	_, m := pauseFixture(t)
	requestReload = func(context.Context) error { return launcher.ErrControlUntrusted }
	err := runDown([]string{"gw-01"})
	if !errors.Is(err, errcode.New(errcode.SettingsNotApplied)) || !errors.Is(err, launcher.ErrControlUntrusted) {
		t.Fatalf("down = %v, want AG116 wrapping the refusal", err)
	}
	if m.reloads != 0 || m.restarts != 0 {
		t.Fatalf("service reloads %d, restarts %d; want none", m.reloads, m.restarts)
	}
}

// A foreground run with no session launcher publishes no states: down does
// not wait the full poll for them.
func TestForegroundRunWithoutALauncherIsNotPolled(t *testing.T) {
	pauseFixture(t)
	requestReload = func(context.Context) error { return nil }
	readDocument = func(context.Context) (*status.Document, error) { return nil, launcher.ErrUnavailable }
	start := time.Now()
	if err := runDown([]string{"gw-01"}); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d >= awaitStatesFor/2 {
		t.Fatalf("down took %v polling a launcher that does not exist", d)
	}
}

// Without a row in the service's document a device's state comes from disk:
// removed (a tombstone and no credential), paused, or configured. A row wins
// over disk.
func TestDeviceStateFallsBackToDisk(t *testing.T) {
	t.Setenv(identity.HomeEnv, t.TempDir())
	asUnprivileged(t)
	store, err := currentInvoker(false).store()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureRoot(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(store.Dir(gw02)), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Forget(context.Background(), gw02, identity.CodeDeviceUnknown, ""); err != nil {
		t.Fatal(err)
	}
	empty := &status.Document{Version: status.Version}
	for _, c := range []struct {
		name string
		doc  *status.Document
		d    config.LocalDevice
		want string
	}{
		{"no document, configured", nil, config.LocalDevice{Identity: gw01}, "configured"},
		{"no row, paused", empty, config.LocalDevice{Identity: gw01, Paused: true}, "paused"},
		{"no row, removed", empty, config.LocalDevice{Identity: gw02, Paused: true}, "removed: refused with SE018"},
		{"row wins", &status.Document{Version: status.Version, Devices: []status.Device{{Identity: gw02.Identity, State: status.StateRunning}}},
			config.LocalDevice{Identity: gw02}, "running"},
	} {
		if got := deviceState(c.doc, store, c.d); !strings.HasPrefix(got, c.want) {
			t.Errorf("%s: %q, want it to start with %q", c.name, got, c.want)
		}
	}
	if got := deviceState(nil, nil, config.LocalDevice{Identity: gw02}); got != "configured" {
		t.Errorf("unreadable store: %q, want configured", got)
	}
}

// With several devices and a terminal, down asks which one with the config's
// lock free, then pauses the chosen device as read again under the lock.
func TestDownAsksWithTheConfigLockFree(t *testing.T) {
	file, _ := pauseFixture(t)
	prevTTY, prevAsk := pickerTTY, askDevices
	t.Cleanup(func() { pickerTTY, askDevices = prevTTY, prevAsk })
	pickerTTY = func() bool { return true }
	askDevices = func(devices []config.LocalDevice, _ map[identity.Ref]deviceFact) ([]int, error) {
		if held, err := configLockHeld(file); err != nil || held {
			t.Errorf("the config lock was held while down asked (%v, %v)", held, err)
			return nil, errors.New("lock held")
		}
		return []int{slices.IndexFunc(devices, func(d config.LocalDevice) bool { return d.Identity == gw02 })}, nil
	}
	if err := runDown(nil); err != nil {
		t.Fatal(err)
	}
	if got := pausedOf(t, file); got[gw01] || !got[gw02] {
		t.Fatalf("paused after choosing gw-02: %v, want gw-02 only", got)
	}
}

// Root's status prints the service state and the account check itself; the
// agent account's half, which cannot read /etc/shadow, prints neither.
func TestAgentChildStatusLeavesTheAccountToRoot(t *testing.T) {
	asRoot(t, &fakeManager{installed: true})
	prevCheck, prevChild := checkAccount, asAgentChild
	t.Cleanup(func() { checkAccount, asAgentChild = prevCheck, prevChild })
	checks := 0
	checkAccount = func(context.Context) (service.Account, error) { checks++; return service.Account{UID: 450}, nil }
	asAgentChild = true
	var out bytes.Buffer
	if err := printStatus(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	if checks != 0 || strings.Contains(out.String(), "service ") || strings.Contains(out.String(), "account ") {
		t.Fatalf("the agent child printed the header (%d account checks): %q", checks, out.String())
	}
	asAgentChild = false
	out.Reset()
	if err := printStatus(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	if checks != 1 || !strings.Contains(out.String(), "account ") {
		t.Fatalf("an in-process status skipped the account line: %q", out.String())
	}
}

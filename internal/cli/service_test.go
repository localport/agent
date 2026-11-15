package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/hpke"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/security"
	"github.com/localport/agent/internal/service"
)

// fakeManager is a service.Manager that records what it was asked.
type fakeManager struct {
	checkErr, installErr, uninstallErr error
	installedErr                       error
	installed                          bool
	mainPID                            int
	installs, uninstalls, reloads      int
}

func (f *fakeManager) Name() string                  { return "localport-device.service" }
func (f *fakeManager) Check() ([]string, error)      { return nil, f.checkErr }
func (f *fakeManager) Installed() (bool, error)      { return f.installed, f.installedErr }
func (f *fakeManager) Restart(context.Context) error { return nil }
func (f *fakeManager) Reload(context.Context) error  { f.reloads++; return nil }
func (f *fakeManager) MainPID(context.Context) (int, error) {
	return f.mainPID, nil
}
func (f *fakeManager) Install(context.Context, string) error {
	f.installs++
	return f.installErr
}
func (f *fakeManager) Uninstall(context.Context) error {
	f.uninstalls++
	return f.uninstallErr
}

// asRoot runs the test's commands as a privileged process whose machine-wide
// config directory is a fresh path under a temp directory, not yet created,
// with m as the service manager and an accepted binary. It returns the
// config file.
func asRoot(t *testing.T, m *fakeManager) config.LocalConfigFile {
	t.Helper()
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(tmp, security.DeviceDirName)
	file := config.LocalConfigFile{Path: filepath.Join(dir, "agent.yaml"), Base: dir}
	restore := []func(){
		func(p func() bool) func() { return func() { privilegedProcess = p } }(privilegedProcess),
		func(p func() (config.LocalConfigFile, error)) func() { return func() { systemLocalConfig = p } }(systemLocalConfig),
		func(p func() (service.Manager, error)) func() { return func() { newServiceManager = p } }(newServiceManager),
		func(p func(string) error) func() { return func() { checkServiceBinary = p } }(checkServiceBinary),
		func(p func()) func() { return func() { ignoreHangup = p } }(ignoreHangup),
		func(p func(bool, string)) func() { return func() { systemLog = p } }(systemLog),
	}
	t.Cleanup(func() {
		for _, r := range restore {
			r()
		}
	})
	privilegedProcess = func() bool { return true }
	systemLocalConfig = func() (config.LocalConfigFile, error) { return file, nil }
	newServiceManager = func() (service.Manager, error) { return m, nil }
	checkServiceBinary = func(string) error { return nil }
	ignoreHangup = func() {}
	systemLog = func(bool, string) {}
	return file
}

// fakeEnrol replaces the enrolment and the credential save, and counts the
// enrolment requests.
func fakeEnrol(t *testing.T, ref identity.Ref) *int {
	t.Helper()
	calls := 0
	prevEnrol, prevSave := enrolDevice, saveIssued
	t.Cleanup(func() { enrolDevice, saveIssued = prevEnrol, prevSave })
	enrolDevice = func(*identity.Client, context.Context, string, time.Duration, identity.RetryNotice) (*identity.Material, error) {
		calls++
		return &identity.Material{}, nil
	}
	saveIssued = func(*identity.Store, context.Context, identity.Material) (identity.Ref, error) { return ref, nil }
	return &calls
}

var connectArgs = []string{"lpj_x", "--api", "https://127.0.0.1:1", "--wait", "0"}

// holdRun holds run.lock of file, as another localport run would, until the
// test ends.
func holdRun(t *testing.T, file config.LocalConfigFile) {
	t.Helper()
	release, err := config.LockRun(file, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = release() })
}

// The service usage and AG043 name the five managers service.Default picks
// from (internal/service default_linux.go, default_darwin.go, windows.go).
func TestServiceTextsNameEveryManager(t *testing.T) {
	unsupported := errcode.New(errcode.Unsupported).Error()
	for _, manager := range []string{"systemd", "OpenRC", "procd", "launchd", "Windows service"} {
		if !strings.Contains(serviceUsage, manager) {
			t.Errorf("service usage does not name %s", manager)
		}
		if !strings.Contains(unsupported, manager) {
			t.Errorf("AG043 does not name %s", manager)
		}
	}
}

// A privileged connect refuses, before any enrolment request, a foreign
// service definition, a binary someone other than root could replace, a
// manual run holding run.lock with no device service installed, and
// --foreground while another process holds run.lock.
func TestPrivilegedConnectRefusesBeforeTheSpend(t *testing.T) {
	for _, c := range []struct {
		name    string
		m       fakeManager
		bin     error
		holdRun bool
		extra   []string
		want    error
	}{
		{name: "foreign definition", m: fakeManager{checkErr: service.ErrForeignUnit}, want: service.ErrForeignUnit},
		{name: "unsafe binary", bin: security.ErrUnsafeExecutable, want: security.ErrUnsafeExecutable},
		{name: "manual run holds run.lock", holdRun: true, want: config.ErrRunLocked},
		{name: "run.lock held beside a service with another main process", m: fakeManager{installed: true, mainPID: os.Getpid() + 1}, holdRun: true, want: config.ErrRunLocked},
		{name: "run.lock held while the service is in a transient state", m: fakeManager{installed: true}, holdRun: true, want: config.ErrRunLocked},
		{name: "foreground beside the running service", m: fakeManager{installed: true}, holdRun: true, extra: []string{"--foreground"}, want: config.ErrRunLocked},
		{name: "foreground beside a manual run", holdRun: true, extra: []string{"--foreground"}, want: config.ErrRunLocked},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := c.m
			file := asRoot(t, &m)
			if c.bin != nil {
				checkServiceBinary = func(string) error { return c.bin }
			}
			if c.holdRun {
				holdRun(t, file)
			}
			calls := fakeEnrol(t, deviceRef("factory.gw-01"))
			err := runConnect("test", append(slices.Clone(connectArgs), c.extra...))
			if !errors.Is(err, c.want) {
				t.Fatalf("connect = %v, want %v", err, c.want)
			}
			if c.holdRun && !slices.Contains(c.extra, "--foreground") && !strings.Contains(err.Error(), fmt.Sprintf("process %d", os.Getpid())) {
				t.Fatalf("connect = %v, want the refusal to name the holder PID %d", err, os.Getpid())
			}
			if *calls != 0 || m.installs != 0 {
				t.Fatalf("connect sent %d enrolment requests and %d installs after the refusal", *calls, m.installs)
			}
		})
	}
}

// --no-mux is refused before the spend when connect installs the service,
// which would serve the device with the mux.
func TestPrivilegedConnectRefusesNoMuxForTheService(t *testing.T) {
	m := &fakeManager{}
	asRoot(t, m)
	calls := fakeEnrol(t, deviceRef("factory.gw-01"))
	err := runConnect("test", append(slices.Clone(connectArgs), "--no-mux"))
	if err == nil || !strings.Contains(err.Error(), "--no-mux applies only to a device run in this terminal") {
		t.Fatalf("connect --no-mux as root = %v, want a refusal", err)
	}
	if *calls != 0 || m.installs != 0 {
		t.Fatalf("connect sent %d enrolment requests and %d installs after the refusal", *calls, m.installs)
	}
}

// With the device service installed, the run.lock holder is that service:
// connect enrols and reinstalls (restarts) it.
func TestConnectBesideTheRunningServiceInstalls(t *testing.T) {
	// The test process holds run.lock and stands in for the service's main
	// process.
	m := &fakeManager{installed: true, mainPID: os.Getpid()}
	file := asRoot(t, m)
	holdRun(t, file)
	calls := fakeEnrol(t, deviceRef("factory.gw-01"))
	if err := runConnect("test", connectArgs); err != nil {
		t.Fatal(err)
	}
	if *calls != 1 || m.installs != 1 {
		t.Fatalf("enrolments %d, installs %d, want 1 and 1", *calls, m.installs)
	}
}

// testRecordingKey is a team recording key the key store accepts.
func testRecordingKey(t *testing.T) string {
	t.Helper()
	priv, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
}

// Connect writes the enrolled session CA keys after the credential is saved. A
// key store failure only warns: the credential stays saved and enrolment
// completes. Only a ticket_keys.json it cannot read gets the file remedy.
func TestConnectWritesTheEnrolledTicketKeysAndWarnsWhenItCannot(t *testing.T) {
	usable := identity.DeviceKeys{
		TicketKeys:   []identity.TicketKey{{KID: "k1", PublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))}},
		RecordingKey: testRecordingKey(t),
	}
	unusable := identity.DeviceKeys{TicketKeys: []identity.TicketKey{{KID: "K!"}}}
	const remedy = "fix its mode to owner-only, or remove it if it is malformed, owned by another user or not a regular file, and the next key fetch or renewal writes the set"
	for _, c := range []struct {
		name     string
		set      identity.DeviceKeys
		existing string
		warns    bool
		remedy   bool
	}{
		{name: "absent file", set: usable},
		{name: "unreadable file", set: usable, existing: `{"keys":[{"kid":"K!","public_key":""}]}`, warns: true, remedy: true},
		{name: "unusable API set", set: unusable, warns: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := &fakeManager{installed: true, mainPID: os.Getpid()}
			holdRun(t, asRoot(t, m))
			ref := deviceRef("factory.gw-01")
			fakeEnrol(t, ref)
			enrolDevice = func(*identity.Client, context.Context, string, time.Duration, identity.RetryNotice) (*identity.Material, error) {
				return &identity.Material{DeviceKeys: &c.set}, nil
			}
			saves := 0
			var store *identity.Store
			saveIssued = func(s *identity.Store, _ context.Context, _ identity.Material) (identity.Ref, error) {
				saves++
				store = s
				if err := os.MkdirAll(s.Dir(ref), 0o700); err != nil {
					return identity.Ref{}, err
				}
				if c.existing != "" {
					return ref, security.WritePrivateFileAtomic(filepath.Join(s.Dir(ref), "ticket_keys.json"), []byte(c.existing))
				}
				return ref, nil
			}

			var err error
			stderr := captureStderr(t, func() { err = runConnect("test", connectArgs) })
			if err != nil {
				t.Fatalf("connect: %v", err)
			}
			if saves != 1 {
				t.Fatalf("credential saves = %d, want 1", saves)
			}
			warned := strings.Contains(stderr, "session keys were not saved to "+filepath.Join(store.Dir(ref), "ticket_keys.json"))
			if gaveRemedy := strings.Contains(stderr, remedy); warned != c.warns || gaveRemedy != c.remedy {
				t.Fatalf("warned = %v, remedy = %v, want %v and %v; stderr:\n%s", warned, gaveRemedy, c.warns, c.remedy, stderr)
			}
			if c.warns {
				return
			}
			keys, err := (&identity.Store{Root: store.Root}).TicketKeys(ref)
			if err != nil {
				t.Fatal(err)
			}
			if err := keys.Load(); err != nil {
				t.Fatal(err)
			}
			if _, ok := keys.Lookup("k1"); !ok {
				t.Fatal("the enrolled session CA key was not stored")
			}
		})
	}
}

// An install failure after the spend keeps the credential and the config
// and names the token-free remedy.
func TestInstallFailureAfterTheSpendNamesServiceInstall(t *testing.T) {
	m := &fakeManager{installErr: errors.New("systemctl restart failed")}
	file := asRoot(t, m)
	ref := deviceRef("factory.gw-01")
	calls := fakeEnrol(t, ref)
	err := runConnect("test", connectArgs)
	if err == nil || !strings.Contains(err.Error(), serviceInstallCommand) || strings.Contains(err.Error(), joinTokenSpent) {
		t.Fatalf("connect = %v, want the service install remedy and no spent-token remedy", err)
	}
	if *calls != 1 || m.installs != 1 {
		t.Fatalf("enrolments %d, installs %d, want 1 and 1", *calls, m.installs)
	}
	if devices := reload(t, file); len(devices) != 1 || devices[0].Identity != ref {
		t.Fatalf("config = %+v, want the enrolled device", devices)
	}
}

func TestServiceCommandsNeedRoot(t *testing.T) {
	m := &fakeManager{}
	asRoot(t, m)
	privilegedProcess = func() bool { return false }
	for _, sub := range []string{"install", "uninstall"} {
		if err := runService([]string{sub}); err == nil || !strings.Contains(err.Error(), "sudo") {
			t.Errorf("non-root service %s = %v, want a refusal naming sudo", sub, err)
		}
	}
	if m.installs+m.uninstalls != 0 {
		t.Fatal("a non-root service command reached the service manager")
	}
}

func TestServiceInstall(t *testing.T) {
	m := &fakeManager{}
	file := asRoot(t, m)
	if err := runService([]string{"install"}); !errors.Is(err, errNoDevice) || m.installs != 0 {
		t.Fatalf("install with no device = %v (installs %d), want errNoDevice", err, m.installs)
	}
	if err := config.WriteLocal(file, &config.LocalConfig{Devices: []config.LocalDevice{{Identity: deviceRef("factory.gw-01")}}}, deviceRef("factory.gw-01")); err != nil {
		t.Fatal(err)
	}
	checkServiceBinary = func(string) error { return security.ErrUnsafeExecutable }
	if err := runService([]string{"install"}); !errors.Is(err, security.ErrUnsafeExecutable) || m.installs != 0 {
		t.Fatalf("install with an unsafe binary = %v (installs %d)", err, m.installs)
	}
	checkServiceBinary = func(string) error { return nil }
	release, err := config.LockRun(file, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := runService([]string{"install"}); !errors.Is(err, config.ErrRunLocked) || m.installs != 0 {
		t.Fatalf("install while a manual run holds run.lock = %v (installs %d), want ErrRunLocked", err, m.installs)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if err := runService([]string{"install"}); err != nil || m.installs != 1 {
		t.Fatalf("install = %v (installs %d), want one install", err, m.installs)
	}
}

func TestServiceUninstallWithNothingToRemoveExitsZero(t *testing.T) {
	asRoot(t, &fakeManager{uninstallErr: service.ErrNotInstalled})
	if err := runService([]string{"uninstall"}); err != nil {
		t.Fatalf("uninstall with no service = %v, want nil", err)
	}
	asRoot(t, nil)
	newServiceManager = func() (service.Manager, error) { return nil, service.ErrUnsupported }
	if err := runService([]string{"uninstall"}); err != nil {
		t.Fatalf("uninstall with no service manager = %v, want nil", err)
	}
}

// writeDevices fills the config directory with a config, a credential and
// the lock file.
func writeDevices(t *testing.T, file config.LocalConfigFile) {
	t.Helper()
	ref := deviceRef("factory.gw-01")
	if err := config.WriteLocal(file, &config.LocalConfig{Devices: []config.LocalDevice{{Identity: ref}}}, ref); err != nil {
		t.Fatal(err)
	}
	cred := filepath.Join(file.Base, "identity", ref.Team, "device-factory.gw-01")
	if err := os.MkdirAll(cred, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cred, "key.pem"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPurgeStopsAtAForeignDefinition(t *testing.T) {
	file := asRoot(t, &fakeManager{uninstallErr: service.ErrForeignUnit})
	writeDevices(t, file)
	if err := runService([]string{"uninstall", "--purge"}); !errors.Is(err, service.ErrForeignUnit) {
		t.Fatalf("uninstall --purge = %v, want ErrForeignUnit", err)
	}
	if _, err := os.Stat(file.Path); err != nil {
		t.Fatalf("the config was deleted despite the refusal: %v", err)
	}
}

// writeSpool puts a recording entry in the recording spool of the system
// store (in the identity directory off Windows) and returns the spool
// directory.
func writeSpool(t *testing.T, file config.LocalConfigFile) string {
	t.Helper()
	store, err := identity.SystemStore(file.Base)
	if err != nil {
		t.Fatal(err)
	}
	spool := recordingSpoolDir(store)
	entry := filepath.Join(spool, "11111111-1111-4111-8111-111111111111")
	if err := os.MkdirAll(entry, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(entry, "meta.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	return spool
}

func TestUninstallKeepsTheDevicesAndRecordingSpool(t *testing.T) {
	file := asRoot(t, &fakeManager{})
	writeDevices(t, file)
	spool := writeSpool(t, file)
	if err := runService([]string{"uninstall"}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{file.Path, filepath.Join(file.Base, "identity"), filepath.Join(spool, "11111111-1111-4111-8111-111111111111", "meta.json")} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("uninstall without --purge deleted %s: %v", p, err)
		}
	}
}

func TestPurgeDeletesTheConfigDeviceCredentialsAndRecordingSpoolOnly(t *testing.T) {
	file := asRoot(t, &fakeManager{uninstallErr: service.ErrNotInstalled})
	writeDevices(t, file)
	writeSpool(t, file)
	other := filepath.Join(file.Base, "notes.txt")
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// A machine credential from setup shares the system store.
	machine := filepath.Join(file.Base, "identity", deviceRef("factory.gw-01").Team, "client-ci-runner")
	if err := os.MkdirAll(machine, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(machine, "key.pem"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runService([]string{"uninstall", "--purge"}); err != nil {
		t.Fatal(err)
	}
	// The lock files and the directory stay, so a concurrent command never
	// locks an unlinked file; anything else in the directory stays too.
	entries, err := os.ReadDir(file.Base)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if want := []string{"agent.yaml.lock", "identity", "notes.txt", "run.lock"}; err != nil || !slices.Equal(names, want) {
		t.Fatalf("directory after purge = %q, %v, want %q", names, err, want)
	}
	if _, err := os.Stat(filepath.Join(machine, "key.pem")); err != nil {
		t.Fatalf("purge deleted the machine credential: %v", err)
	}
	devices, err := filepath.Glob(filepath.Join(file.Base, "identity", "*", "device-*"))
	if err != nil || len(devices) != 0 {
		t.Fatalf("device credentials after purge = %q, %v, want none", devices, err)
	}

	// A missing directory is not created.
	if err := os.RemoveAll(file.Base); err != nil {
		t.Fatal(err)
	}
	if err := runService([]string{"uninstall", "--purge"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file.Base); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("purge created %s: %v", file.Base, err)
	}
}

// --purge refuses while a device service carrying the marker is still
// installed or marked for deletion, and while another process holds
// run.lock; each keeps the devices.
func TestPurgeRefusals(t *testing.T) {
	for _, c := range []struct {
		name    string
		m       fakeManager
		holdRun bool
		want    error
	}{
		{name: "service still installed", m: fakeManager{installed: true}, want: errServiceInstalled},
		{name: "service marked for deletion", m: fakeManager{installed: true, installedErr: service.ErrMarkedForDelete}, want: service.ErrMarkedForDelete},
		{name: "run.lock held", m: fakeManager{uninstallErr: service.ErrNotInstalled}, holdRun: true, want: config.ErrRunLocked},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := c.m
			file := asRoot(t, &m)
			writeDevices(t, file)
			if c.holdRun {
				holdRun(t, file)
			}
			if err := runService([]string{"uninstall", "--purge"}); !errors.Is(err, c.want) {
				t.Fatalf("uninstall --purge = %v, want %v", err, c.want)
			}
			if _, err := os.Stat(file.Path); err != nil {
				t.Fatalf("the config was deleted despite the refusal: %v", err)
			}
		})
	}
}

// A user-launched privileged run is refused at once while run.lock is held,
// naming the device service when it is installed; run --service waits and
// starts once the holder releases it; every privileged run re-checks the
// binary.
func TestPrivilegedRunHoldsRunLock(t *testing.T) {
	m := &fakeManager{installed: true}
	file := asRoot(t, m)
	release, err := config.LockRun(file, 0)
	if err != nil {
		t.Fatal(err)
	}
	notRunning := func() { t.Error("a run refused by the binary check reported running") }
	err = runEnrolledDevices(context.Background(), "test", currentInvoker(false), false, true, func() {})
	if !errors.Is(err, config.ErrRunLocked) || !strings.Contains(err.Error(), m.Name()) {
		t.Fatalf("run beside the holder = %v, want ErrRunLocked naming %s", err, m.Name())
	}

	time.AfterFunc(300*time.Millisecond, func() { _ = release() })
	started := false
	err = runEnrolledDevices(context.Background(), "test", currentInvoker(true), true, true, func() { started = true })
	if errors.Is(err, config.ErrRunLocked) || !started {
		t.Fatalf("run --service after the holder released = %v (started %v), want it past the lock", err, started)
	}

	// A stop request cancels the context, which ends the wait; running was
	// reported before it, so the Windows service accepts that Stop.
	held, err := config.LockRun(file, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	started = false
	err = runEnrolledDevices(ctx, "test", currentInvoker(true), true, true, func() { started = true })
	if !errors.Is(err, context.Canceled) || !started {
		t.Fatalf("run --service stopped during the wait = %v (started %v), want context.Canceled after running", err, started)
	}

	// Giving up the wait exits with ExitRunLocked.
	serviceRunLockWait = 300 * time.Millisecond
	t.Cleanup(func() { serviceRunLockWait = 30 * time.Second })
	err = runEnrolledDevices(context.Background(), "test", currentInvoker(true), true, true, func() {})
	var exitErr *service.ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != service.ExitRunLocked || !errors.Is(err, config.ErrRunLocked) {
		t.Fatalf("run --service past its wait = %v, want ExitError %d wrapping ErrRunLocked", err, service.ExitRunLocked)
	}
	if err := held(); err != nil {
		t.Fatal(err)
	}

	checkServiceBinary = func(string) error { return security.ErrUnsafeExecutable }
	for _, asService := range []bool{false, true} {
		if err := runEnrolledDevices(context.Background(), "test", currentInvoker(false), asService, true, notRunning); !errors.Is(err, security.ErrUnsafeExecutable) {
			t.Fatalf("run (service %v) with an unsafe binary = %v, want ErrUnsafeExecutable", asService, err)
		}
	}
}

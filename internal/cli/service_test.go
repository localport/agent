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
	installs, uninstalls               int
}

func (f *fakeManager) Name() string                  { return "localport-device.service" }
func (f *fakeManager) Check() ([]string, error)      { return nil, f.checkErr }
func (f *fakeManager) Installed() (bool, error)      { return f.installed, f.installedErr }
func (f *fakeManager) Restart(context.Context) error { return nil }
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

// Connect writes the enrolled ticket keys after the credential is saved. A
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
			warned := strings.Contains(stderr, "ticket keys were not saved to "+filepath.Join(store.Dir(ref), "ticket_keys.json"))
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
				t.Fatal("the enrolled ticket key was not stored")
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

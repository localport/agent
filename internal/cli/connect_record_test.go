package cli

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/ports"
	"github.com/localport/agent/internal/security"
)

func deviceRef(id string) identity.Ref {
	return identity.Ref{Team: "01kpq7x2abcd34", Kind: identity.KindDevice, Identity: id}
}

// storedConfig writes a local config holding stored under a temp
// LOCALPORT_HOME and returns its file.
func storedConfig(t *testing.T, stored config.LocalDevice) config.LocalConfigFile {
	t.Helper()
	t.Setenv(identity.HomeEnv, t.TempDir())
	file, err := config.UserLocalConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err := config.WriteLocal(file, &config.LocalConfig{Devices: []config.LocalDevice{stored}}, stored.Identity); err != nil {
		t.Fatal(err)
	}
	return file
}

func reload(t *testing.T, file config.LocalConfigFile) []config.LocalDevice {
	t.Helper()
	cfg, err := config.LoadLocal(file)
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Devices
}

func sameDevice(a, b config.LocalDevice) bool { return a.Equal(b) }

func storedDevice(t *testing.T) config.LocalDevice {
	t.Helper()
	allowed, err := ports.ParseFlag("502")
	if err != nil {
		t.Fatal(err)
	}
	return config.LocalDevice{
		Identity:   deviceRef("factory.gw-01"),
		AllowPorts: allowed,
		Enable:     []config.Capability{config.CapabilityTerminal},
		Logins:     []string{"pi"},
	}
}

var piInvoker = invoker{privileged: false, current: "pi", goos: "linux"}

// asUnprivileged runs the test's commands as an unprivileged invoker, so a
// root test run uses LOCALPORT_HOME instead of the system store and config.
func asUnprivileged(t *testing.T) {
	t.Helper()
	saved := privilegedProcess
	privilegedProcess = func() bool { return false }
	t.Cleanup(func() { privilegedProcess = saved })
}

// A re-enrolment without flags keeps the device's ports, capabilities and
// logins.
func TestFlaglessReEnrolKeepsTheStoredSettings(t *testing.T) {
	stored := storedDevice(t)
	file := storedConfig(t, stored)
	fs, flags := parseDeviceFlags(t)
	inForce, err := recordDevice(file, fs, flags, piInvoker, stored.Identity, config.LocalDevice{})
	if err != nil {
		t.Fatal(err)
	}
	if !sameDevice(inForce, stored) {
		t.Fatalf("in force %+v, want the stored %+v", inForce, stored)
	}
	if got := reload(t, file); len(got) != 1 || !sameDevice(got[0], stored) {
		t.Fatalf("config %+v, want the stored entry", got)
	}
}

// Flags given override the stored values; the rest keep theirs.
func TestReEnrolFlagsOverrideTheStoredSettings(t *testing.T) {
	stored := storedDevice(t)
	file := storedConfig(t, stored)
	fs, flags := parseDeviceFlags(t, "--allow-ports", "80")
	inForce, err := recordDevice(file, fs, flags, piInvoker, stored.Identity, config.LocalDevice{})
	if err != nil {
		t.Fatal(err)
	}
	if inForce.AllowPorts.String() != "80" || !slices.Equal(inForce.Logins, []string{"pi"}) || !slices.Equal(inForce.Enable, stored.Enable) {
		t.Fatalf("in force %+v, want ports 80 and the stored terminal and logins", inForce)
	}
}

// An invalid merge leaves the stored entry in force and the config unchanged.
func TestAnInvalidMergeKeepsTheStoredEntry(t *testing.T) {
	stored := config.LocalDevice{Identity: deviceRef("factory.plc-01"), Host: "10.0.0.5"}
	file := storedConfig(t, stored)
	before, err := os.ReadFile(file.Path)
	if err != nil {
		t.Fatal(err)
	}
	// recordDevice must never touch the credential the enrolment saved.
	credential := filepath.Join(os.Getenv(identity.HomeEnv), "identity", "credential")
	if err := os.MkdirAll(filepath.Dir(credential), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credential, []byte("saved"), 0o600); err != nil {
		t.Fatal(err)
	}
	fs, flags := parseDeviceFlags(t, "--enable", "terminal")
	inForce, err := recordDevice(file, fs, flags, piInvoker, stored.Identity, config.LocalDevice{})
	if kept, readErr := os.ReadFile(credential); readErr != nil || string(kept) != "saved" {
		t.Fatalf("the saved credential was touched: %v", readErr)
	}
	if !errors.Is(err, errMergeConflict) || !errors.Is(err, config.ErrHostCapability) {
		t.Fatalf("recordDevice = %v, want errMergeConflict wrapping ErrHostCapability", err)
	}
	if !sameDevice(inForce, stored) {
		t.Fatalf("in force %+v, want the stored entry", inForce)
	}
	after, err := os.ReadFile(file.Path)
	if err != nil || string(after) != string(before) {
		t.Fatalf("the config changed after an invalid merge: %v", err)
	}
}

// A new identity appends its entry.
func TestANewIdentityAppends(t *testing.T) {
	stored := storedDevice(t)
	file := storedConfig(t, stored)
	fs, flags := parseDeviceFlags(t, "--allow-ports", "22")
	fresh, err := prepareDevice(fs, flags, piInvoker)
	if err != nil {
		t.Fatal(err)
	}
	newRef := deviceRef("factory.gw-02")
	if _, err := recordDevice(file, fs, flags, piInvoker, newRef, fresh); err != nil {
		t.Fatal(err)
	}
	got := reload(t, file)
	if len(got) != 2 || !sameDevice(got[0], stored) || got[1].Identity != newRef || got[1].AllowPorts.String() != "22" {
		t.Fatalf("config %+v, want the stored entry and the new one", got)
	}
}

// setup and login check the store directory before spending their one-time
// secret: a store path that is not a directory fails here, never at the
// unroutable API.
func TestSetupAndLoginCheckTheStoreBeforeTheSpend(t *testing.T) {
	asUnprivileged(t)
	for name, run := range map[string]func() error{
		"setup": func() error { return runSetup([]string{"lps_x", "--api", "https://127.0.0.1:1", "--wait", "0"}) },
		"login": func() error { return runLogin([]string{"--api", "https://127.0.0.1:1"}) },
	} {
		home := t.TempDir()
		untrusted := filepath.Join(home, "identity")
		// A file where the store directory belongs: EnsureRoot refuses it.
		if err := os.WriteFile(untrusted, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(identity.HomeEnv, home)
		if err := run(); !errors.Is(err, security.ErrUntrustedPath) {
			t.Errorf("%s = %v, want ErrUntrustedPath before any request", name, err)
		}
	}
}

// A merge whose write fails for another reason is not a flag conflict: it
// prints the spent-token remedy.
func TestAMergeWriteFailureIsNotAConflict(t *testing.T) {
	stored := storedDevice(t)
	file := storedConfig(t, stored)
	failing := errors.New("no space left on device")
	writeLocal = func(config.LocalConfigFile, *config.LocalConfig, identity.Ref) error { return failing }
	t.Cleanup(func() { writeLocal = config.WriteLocal })
	fs, flags := parseDeviceFlags(t, "--allow-ports", "80")
	inForce, err := recordDevice(file, fs, flags, piInvoker, stored.Identity, config.LocalDevice{})
	if errors.Is(err, errMergeConflict) || !errors.Is(err, failing) || !strings.Contains(err.Error(), joinTokenSpent) {
		t.Fatalf("recordDevice = %v, want the write error with the spent-token remedy", err)
	}
	if !sameDevice(inForce, stored) {
		t.Fatalf("in force %+v, want the stored entry", inForce)
	}
	if isDeviceNotRecorded(err) {
		t.Fatal("a stored device keeps its config entry, so its credential is in use")
	}
}

// A new identity whose entry cannot be written is reported as unrecorded, and
// connect removes its credential, so no credential is left that nothing uses.
func TestAnAppendWriteFailureForgetsTheNewCredential(t *testing.T) {
	stored := storedDevice(t)
	file := storedConfig(t, stored)
	failing := &fs.PathError{Op: "write", Path: file.Path, Err: syscall.ENOSPC}
	writeLocal = func(config.LocalConfigFile, *config.LocalConfig, identity.Ref) error { return failing }
	t.Cleanup(func() { writeLocal = config.WriteLocal })
	flagSet, flags := parseDeviceFlags(t)
	newRef := deviceRef("factory.gw-02")
	_, err := recordDevice(file, flagSet, flags, piInvoker, newRef, config.LocalDevice{})
	if !isDeviceNotRecorded(err) || !errors.Is(err, failing) {
		t.Fatalf("recordDevice = %v, want deviceNotRecorded wrapping the write error", err)
	}
	// The marker adds no hidden cause: the user sees the write error in full.
	if text, hidden := errcode.Render(err); !strings.Contains(text, syscall.ENOSPC.Error()) || hidden {
		t.Fatalf("Render = %q, %v; want the write error shown", text, hidden)
	}

	store := &identity.Store{Root: filepath.Join(os.Getenv(identity.HomeEnv), "identity")}
	if err := os.MkdirAll(store.Dir(newRef), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.Dir(newRef), "meta.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := forgetUnrecorded(store, false, newRef); err != nil {
		t.Fatalf("forgetUnrecorded = %v", err)
	}
	if _, err := os.Lstat(store.Dir(newRef)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("credential directory after forgetUnrecorded: %v", err)
	}
}

// A stored files root that has gone missing is reported as such, not as a
// conflict with the flags.
func TestAMissingStoredFilesRootIsNotAFlagConflict(t *testing.T) {
	root := filepath.Join(t.TempDir(), "share")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	stored := storedDevice(t)
	stored.Enable = []config.Capability{config.CapabilityFiles}
	stored.FilesRoot = root
	file := storedConfig(t, stored)
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}

	// Nothing changes: the config is not rewritten, so the missing root is
	// not even checked.
	fs, flags := parseDeviceFlags(t)
	if _, err := recordDevice(file, fs, flags, piInvoker, stored.Identity, config.LocalDevice{}); err != nil {
		t.Fatalf("an unchanged re-enrolment = %v, want no write and no error", err)
	}

	fs, flags = parseDeviceFlags(t, "--allow-ports", "80")
	_, err := recordDevice(file, fs, flags, piInvoker, stored.Identity, config.LocalDevice{})
	if !errors.Is(err, config.ErrFilesRootMissing) || errors.Is(err, errMergeConflict) || strings.Contains(err.Error(), "flags conflict") ||
		strings.Contains(err.Error(), joinTokenSpent) {
		t.Fatalf("recordDevice = %v, want ErrFilesRootMissing, no flag conflict and no spent-token remedy", err)
	}
}

// connect checks the store directory and the local config before it spends
// the join token: both fail here, never at the unroutable API.
func TestConnectChecksTheStoreAndConfigBeforeTheSpend(t *testing.T) {
	asUnprivileged(t)
	args := []string{"lpj_x", "--api", "https://127.0.0.1:1", "--wait", "0"}

	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "identity"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(identity.HomeEnv, home)
	if err := runConnect("test", args); !errors.Is(err, security.ErrUntrustedPath) {
		t.Fatalf("connect with an unusable store = %v, want ErrUntrustedPath before any request", err)
	}

	home = t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "agent.yaml"), []byte("version: 9\ndevices: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(identity.HomeEnv, home)
	if err := runConnect("test", args); !errors.Is(err, config.ErrInvalidLocalConfig) {
		t.Fatalf("connect with a refused config = %v, want ErrInvalidLocalConfig before any request", err)
	}
}

// --no-inspect and --log-requests apply only to a config file and are
// refused beside a join token, before the spend.
func TestConnectRefusesInspectFlagsBesideAJoinToken(t *testing.T) {
	t.Setenv(identity.HomeEnv, t.TempDir())
	calls := fakeEnrol(t, deviceRef("factory.gw-01"))
	for _, flag := range []string{"--no-inspect", "--log-requests"} {
		err := runConnect("test", append(slices.Clone(connectArgs), flag))
		if err == nil || !strings.Contains(err.Error(), flag+" apply only with --config") {
			t.Fatalf("connect %s = %v, want a refusal", flag, err)
		}
	}
	if *calls != 0 {
		t.Fatalf("the refusal spent the join token (%d enrolments)", *calls)
	}
}

// --no-mux reaches the device a foreground connect serves.
func TestConnectNoMuxReachesTheDevice(t *testing.T) {
	// A foreground connect is the unprivileged one; a privileged run would
	// install the service instead.
	asUnprivileged(t)
	stored := config.LocalDevice{Identity: deviceRef("factory.gw-01")}
	storedConfig(t, stored)
	fakeEnrol(t, stored.Identity)
	prev := serveEnrolled
	t.Cleanup(func() { serveEnrolled = prev })
	for _, want := range []bool{false, true} {
		got := !want
		serveEnrolled = func(_ context.Context, _ string, _ *identity.Store, _ []config.LocalDevice, _, noMux bool, _ func() ([]config.LocalDevice, error)) error {
			got = noMux
			return nil
		}
		args := slices.Clone(connectArgs)
		if want {
			args = append(args, "--no-mux")
		}
		if err := runConnect("test", args); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("connect %q served with noMux %v, want %v", args, got, want)
		}
	}
}

// connect removes the credential it just saved when the local config write
// fails, so no enrolled credential is left without a config entry.
func TestConnectForgetsTheCredentialWhenTheConfigWriteFails(t *testing.T) {
	t.Setenv(identity.HomeEnv, t.TempDir())
	ref := deviceRef("factory.gw-03")
	fakeEnrol(t, ref)
	saveIssued = func(store *identity.Store, _ context.Context, _ identity.Material) (identity.Ref, error) {
		if err := os.MkdirAll(store.Dir(ref), 0o700); err != nil {
			return identity.Ref{}, err
		}
		return ref, os.WriteFile(filepath.Join(store.Dir(ref), "meta.json"), []byte("{}"), 0o600)
	}
	failing := errors.New("no space left on device")
	writeLocal = func(config.LocalConfigFile, *config.LocalConfig, identity.Ref) error { return failing }
	t.Cleanup(func() { writeLocal = config.WriteLocal })

	if err := runConnect("test", connectArgs); !isDeviceNotRecorded(err) || !errors.Is(err, failing) {
		t.Fatalf("runConnect = %v, want deviceNotRecorded wrapping the write error", err)
	}
	store := &identity.Store{Root: filepath.Join(os.Getenv(identity.HomeEnv), "identity")}
	if _, err := os.Lstat(store.Dir(ref)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("credential directory after the failed config write: %v", err)
	}
}

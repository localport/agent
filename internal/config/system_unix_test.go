//go:build !windows

package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/security"
)

// systemTestFile is a System config in a temporary device directory, with the
// test's own uid as the system owner and its own gid as the agent group.
// asRoot selects whether this process acts as root (the writer).
func systemTestFile(t *testing.T, asRoot bool) LocalConfigFile {
	t.Helper()
	t.Cleanup(security.OverrideSystemOwner(os.Getuid()))
	setSystemRoot(t, asRoot)
	prevGroup := agentGroupID
	agentGroupID = func() (int, error) { return os.Getgid(), nil }
	t.Cleanup(func() { agentGroupID = prevGroup })
	dir := filepath.Join(t.TempDir(), "localport-device")
	return LocalConfigFile{Path: filepath.Join(dir, localConfigName), Base: dir, System: true}
}

func setSystemRoot(t *testing.T, asRoot bool) {
	t.Helper()
	prev := geteuid
	uid := os.Getuid()
	if !asRoot {
		uid++
	}
	geteuid = func() int { return uid }
	t.Cleanup(func() { geteuid = prev })
}

func systemTestConfig() *LocalConfig {
	ref, _ := identity.ParseDeviceRef("team/device/plc.ab12")
	return &LocalConfig{Devices: []LocalDevice{{Identity: ref}}}
}

func TestSystemConfigWriteAndLoad(t *testing.T) {
	f := systemTestFile(t, true)
	cfg := systemTestConfig()
	if err := WriteLocal(f, cfg, cfg.Devices[0].Identity); err != nil {
		t.Fatalf("WriteLocal: %v", err)
	}
	for path, want := range map[string]os.FileMode{filepath.Dir(f.Path): 0o750, f.Path: 0o640} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != want {
			t.Errorf("%s mode %#o, want %#o", path, perm, want)
		}
	}
	setSystemRoot(t, false)
	got, err := LoadLocal(f)
	if err != nil {
		t.Fatalf("LoadLocal as the agent account: %v", err)
	}
	if len(got.Devices) != 1 || got.Devices[0].Identity != cfg.Devices[0].Identity {
		t.Fatalf("loaded %+v", got.Devices)
	}
}

func TestSystemConfigLoadRefusesWritableFile(t *testing.T) {
	f := systemTestFile(t, true)
	cfg := systemTestConfig()
	if err := WriteLocal(f, cfg, cfg.Devices[0].Identity); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.Path, 0o660); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLocal(f); !errors.Is(err, security.ErrUntrustedPath) {
		t.Fatalf("LoadLocal of a group-writable config = %v, want ErrUntrustedPath", err)
	}
}

func TestSystemConfigWriteRefusesNonRoot(t *testing.T) {
	f := systemTestFile(t, false)
	cfg := systemTestConfig()
	if err := WriteLocal(f, cfg, cfg.Devices[0].Identity); !errors.Is(err, ErrSystemNotRoot) {
		t.Fatalf("WriteLocal as non-root = %v, want ErrSystemNotRoot", err)
	}
	if _, err := LockLocal(f); !errors.Is(err, ErrSystemNotRoot) {
		t.Fatalf("LockLocal as non-root = %v, want ErrSystemNotRoot", err)
	}
	if _, err := os.Stat(filepath.Dir(f.Path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a non-root process created the device directory")
	}
}

func TestSystemConfigWriteNamesInstallWhenGroupMissing(t *testing.T) {
	f := systemTestFile(t, true)
	agentGroupID = func() (int, error) { return 0, security.ErrAgentGroupMissing }
	cfg := systemTestConfig()
	err := WriteLocal(f, cfg, cfg.Devices[0].Identity)
	if !errors.Is(err, security.ErrAgentGroupMissing) {
		t.Fatalf("WriteLocal without the group = %v, want ErrAgentGroupMissing", err)
	}
}

// Root creates run.lock root:security.AgentGroup 0660; the agent account then opens the
// existing file without creating it and locks it.
func TestSystemRunLock(t *testing.T) {
	f := systemTestFile(t, false)
	if _, err := LockRun(f, 0); err == nil {
		t.Fatal("the agent account locked a run.lock root never created")
	}
	setSystemRoot(t, true)
	if err := EnsureSystemRunLock(f); err != nil {
		t.Fatalf("EnsureSystemRunLock: %v", err)
	}
	info, err := os.Stat(f.RunLockPath())
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o660 {
		t.Fatalf("run.lock mode %#o, want 0660", perm)
	}
	setSystemRoot(t, false)
	release, err := LockRun(f, 0)
	if err != nil {
		t.Fatalf("LockRun as the agent account: %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	setSystemRoot(t, true)
	unlock, err := LockLocal(f)
	if err != nil {
		t.Fatalf("LockLocal as root: %v", err)
	}
	unlock()
	if info, err := os.Lstat(f.LockPath()); err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("config lock directory = %v, %v; want a directory with mode 0700", info, err)
	}
	if info, err := os.Lstat(filepath.Join(f.LockPath(), configLockMarker)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config lock marker = %v, %v; want mode 0600", info, err)
	}
}

// The agent account refuses a device directory another account can write,
// before it opens anything in it.
func TestSystemRunLockRefusesWritableDir(t *testing.T) {
	f := systemTestFile(t, true)
	if err := EnsureSystemRunLock(f); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(f.Path), 0o770); err != nil {
		t.Fatal(err)
	}
	setSystemRoot(t, false)
	if _, err := LockRun(f, 0); !errors.Is(err, security.ErrUntrustedPath) {
		t.Fatalf("LockRun in a group-writable dir = %v, want ErrUntrustedPath", err)
	}
}

// The system config may hold no device: removing the last one writes an empty
// list, and the device service loads it and idles.
func TestSystemConfigHoldsNoDevice(t *testing.T) {
	f := systemTestFile(t, true)
	if err := WriteLocal(f, &LocalConfig{}, identity.Ref{}); err != nil {
		t.Fatalf("WriteLocal(no devices): %v", err)
	}
	setSystemRoot(t, false)
	got, err := LoadLocal(f)
	if err != nil || len(got.Devices) != 0 {
		t.Fatalf("LoadLocal = %+v, %v; want an empty device list", got, err)
	}
}

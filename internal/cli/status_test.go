package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/status"
)

func TestStatusPrintsServiceAndDevices(t *testing.T) {
	file := asRoot(t, &fakeManager{installed: true, mainPID: 42})
	writeDevices(t, file)
	var out bytes.Buffer
	if err := printStatus(context.Background(), &out); err != nil {
		t.Fatalf("status = %v", err)
	}
	launcher := "launcher   session auth"
	if runtime.GOOS == "windows" {
		launcher = "launcher   session logon state: see the device in the dashboard"
	}
	for _, want := range []string{"running, pid 42", "config     " + file.Path, "device     " + deviceRef("factory.gw-01").String(), "run_as_agent false", launcher} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status output lacks %q:\n%s", want, out.String())
		}
	}
}

// A running service whose run lock another process holds stands by: status
// says it waits and names the holder. Once that process releases the lock,
// even with its PID left in run.lock, status shows the service as running.
func TestStatusShowsAStandingByService(t *testing.T) {
	file := asRoot(t, &fakeManager{installed: true, mainPID: 42})
	writeDevices(t, file)
	release, err := config.LockRun(file, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := printServiceState(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("running, pid 42, waiting: a foreground run (pid %d) serves the devices", os.Getpid())
	if !strings.Contains(out.String(), want) {
		t.Fatalf("status with a foreground run holding the lock:\n%s\nwant %q", out.String(), want)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file.RunLockPath(), []byte("\n7777\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := printServiceState(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); strings.Contains(got, "waiting") || !strings.Contains(got, "running, pid 42") {
		t.Fatalf("status after the holder released, with a stale PID left:\n%s", got)
	}
}

// An unprivileged reader of the system config (a member of the agent group)
// has its own store, which holds none of the system devices: a tombstone
// there never marks a system device removed.
func TestStatusOfTheSystemConfigIgnoresTheReadersStore(t *testing.T) {
	file := asRoot(t, &fakeManager{installed: true, mainPID: 42})
	writeDevices(t, file)
	privilegedProcess = func() bool { return false }
	t.Setenv(identity.HomeEnv, t.TempDir())
	saved := readDocument
	readDocument = func(context.Context) (*status.Document, error) { return nil, launcher.ErrUnavailable }
	t.Cleanup(func() { readDocument = saved })
	own, err := currentInvoker(false).store()
	if err != nil {
		t.Fatal(err)
	}
	ref := deviceRef("factory.gw-01")
	storeDevice(t, own, ref, "http://"+closedAddr(t))
	if ok, err := own.Forget(context.Background(), ref, identity.CodeDeviceUnknown, "07"); !ok || err != nil {
		t.Fatalf("Forget = %v, %v", ok, err)
	}
	var out bytes.Buffer
	if err := printStatusDevices(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); strings.Contains(got, "removed") || !strings.Contains(got, "configured") {
		t.Fatalf("status of the system config read by a group member:\n%s", got)
	}
}

// Without a readable config, status prints the service state only.
func TestStatusWithoutConfigPrintsServiceOnly(t *testing.T) {
	asRoot(t, &fakeManager{})
	var out bytes.Buffer
	if err := printStatus(context.Background(), &out); err != nil {
		t.Fatalf("status = %v", err)
	}
	if got := out.String(); !strings.Contains(got, "not installed") || !strings.Contains(got, "config     none at") || strings.Contains(got, "device ") {
		t.Fatalf("status output:\n%s", got)
	}
}

package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"testing"
	"time"
)

// configHolderEnv makes the test binary a child that takes the service
// configuration lock, holds it until its stdin closes, and reports each step
// on stdout: "waiting" once it holds the namespace and mutex handles,
// "held" once it owns the mutex, "error: <text>" when the take fails. A
// private namespace can be open only once per process, so another holder
// must be another process, as the installer and the CLI are.
const configHolderEnv = "LOCALPORT_TEST_SERVICE_CONFIG_HOLDER"

func TestMain(m *testing.M) {
	if os.Getenv(configHolderEnv) != "" {
		os.Exit(holdServiceConfigChild())
	}
	os.Exit(runWithPrivateProgramData(m))
}

// runWithPrivateProgramData points %ProgramData% at a temporary directory for
// the whole run, so no test reaches the machine's device config, identity or
// crash directories, which every system path derives from it.
func runWithPrivateProgramData(m *testing.M) int {
	dir, err := os.MkdirTemp("", "localport-programdata-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "create the test ProgramData:", err)
		return 1
	}
	defer os.RemoveAll(dir)
	if err := os.Setenv("ProgramData", dir); err != nil {
		fmt.Fprintln(os.Stderr, "set the test ProgramData:", err)
		return 1
	}
	return m.Run()
}

func holdServiceConfigChild() int {
	serviceConfigWaiting = func() { fmt.Println("waiting") }
	runtime.LockOSThread()
	unlock, err := lockServiceConfig(context.Background())
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return 1
	}
	fmt.Println("held")
	_, _ = io.Copy(io.Discard, os.Stdin)
	unlock()
	return 0
}

// configHolder is a child process holding, or waiting for, the lock.
type configHolder struct {
	stdin   io.WriteCloser
	lines   chan string
	held    bool
	release func()
}

// startConfigHolder starts a holder; the test's cleanup releases it.
func startConfigHolder(t *testing.T) *configHolder {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), configHolderEnv+"=1")
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	h := &configHolder{stdin: stdin, lines: make(chan string, 4)}
	go func() {
		defer close(h.lines)
		s := bufio.NewScanner(stdout)
		for s.Scan() {
			h.lines <- s.Text()
		}
	}()
	var once sync.Once
	h.release = func() {
		once.Do(func() {
			_ = stdin.Close()
			// A holder still waiting for the lock reads stdin only once it
			// holds it; end it rather than wait out serviceConfigLockWait.
			if !h.held {
				_ = cmd.Process.Kill()
			}
			// os/exec: read all of stdout before Wait closes it.
			for range h.lines {
			}
			if !h.held {
				_ = cmd.Wait()
				return
			}
			if err := cmd.Wait(); err != nil {
				t.Errorf("service configuration holder: %v", err)
			}
		})
	}
	t.Cleanup(h.release)
	return h
}

// expect fails the test unless the holder's next report is want.
func (h *configHolder) expect(t *testing.T, want string) {
	t.Helper()
	select {
	case got, ok := <-h.lines:
		if !ok || got != want {
			t.Fatalf("service configuration holder reported %q (open %v), want %q", got, ok, want)
		}
		h.held = h.held || want == "held"
	case <-time.After(30 * time.Second):
		t.Fatalf("service configuration holder did not report %q", want)
	}
}

func requireElevated(t *testing.T) {
	t.Helper()
	if !privileged() {
		t.Skip("the service configuration namespace needs an elevated Administrator")
	}
}

func shortServiceConfigWait(t *testing.T) {
	t.Helper()
	old := serviceConfigLockWait
	serviceConfigLockWait = time.Second
	t.Cleanup(func() { serviceConfigLockWait = old })
}

// Every writer of the service definitions refuses with AG091 while another
// process holds the lock, before it changes anything. The writers run one
// after another in this process, so each opens the namespace again after the
// last one closed it.
func TestServiceWritersRefuseWhileTheConfigLockIsHeld(t *testing.T) {
	requireElevated(t)
	shortServiceConfigWait(t)
	holder := startConfigHolder(t)
	holder.expect(t, "waiting")
	holder.expect(t, "held")

	writers := map[string]func() error{
		"service install":   func() error { return installService(currentInvoker(true)) },
		"service uninstall": func() error { return uninstallService(currentInvoker(true), false) },
		"connect":           func() error { return (&deviceService{}).install() },
	}
	for name, write := range writers {
		if err := write(); !errors.Is(err, errServiceConfigBusy) || !errors.Is(err, errServiceConfigHeld) {
			t.Errorf("%s = %v, want errServiceConfigBusy after waiting for the holder", name, err)
		}
	}
}

// The lock stays one mutex when its first holder, the namespace's creator,
// exits while a second holder that opened the namespace waits for it: the
// second then holds it, and a third writer must wait.
func TestServiceConfigLockSurvivesItsCreatorClosing(t *testing.T) {
	requireElevated(t)
	shortServiceConfigWait(t)
	first := startConfigHolder(t)
	first.expect(t, "waiting")
	first.expect(t, "held")
	second := startConfigHolder(t)
	second.expect(t, "waiting")
	first.release()
	second.expect(t, "held")

	// This process opens the namespace after its creator closed it and must
	// wait on the same mutex: it times out while the second holds it,
	// rather than failing to open or taking a different mutex.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	unlock, err := lockServiceConfig(context.Background())
	if err == nil {
		unlock()
		t.Fatal("a third writer took the lock while the second held it")
	}
	if !errors.Is(err, errServiceConfigHeld) {
		t.Fatalf("third writer = %v, want a wait that timed out (errServiceConfigHeld)", err)
	}
	second.release()
	unlock, err = lockServiceConfig(context.Background())
	if err != nil {
		t.Fatalf("third writer after the second released = %v", err)
	}
	unlock()
}

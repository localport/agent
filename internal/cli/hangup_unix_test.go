//go:build unix

package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/localport/agent/internal/service"
)

// The roles of the test binary re-executed by TestHangupSafeCommandsRunToTheEnd.
const (
	hangupRoleEnv    = "LOCALPORT_TEST_HANGUP_ROLE"
	hangupOutcomeEnv = "LOCALPORT_TEST_HANGUP_OUTCOME"
	hangupCommand    = "command"
	hangupManager    = "manager"
	hangupHelperRun  = "-test.run=^TestHangupSafeHelper$"
)

// hangupManagerProcess is a service.Manager whose Install, Restart and
// Uninstall run the test binary as the service manager command, as execRun
// runs systemctl.
type hangupManagerProcess struct{ fakeManager }

func (hangupManagerProcess) run(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, os.Args[0], hangupHelperRun)
	cmd.Env = append(os.Environ(), hangupRoleEnv+"="+hangupManager)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("service manager command: %w: %s", err, out)
	}
	return nil
}

func (m *hangupManagerProcess) Install(ctx context.Context, _ string) error { return m.run(ctx) }
func (m *hangupManagerProcess) Restart(ctx context.Context) error           { return m.run(ctx) }
func (m *hangupManagerProcess) Reload(ctx context.Context) error            { return m.run(ctx) }
func (m *hangupManagerProcess) Uninstall(ctx context.Context) error         { return m.run(ctx) }

// TestHangupSafeHelper is the re-executed test binary. As the command it runs
// set, service install, service uninstall or connect as root against
// hangupManagerProcess with the production dispositions, and writes the
// outcome line to a file. As the service manager it hangs up its process
// group, command included, as the end of a terminal session does, and
// succeeds.
func TestHangupSafeHelper(t *testing.T) {
	switch os.Getenv(hangupRoleEnv) {
	case hangupCommand:
		m := &hangupManagerProcess{fakeManager{installed: true}}
		file := asRoot(t, &m.fakeManager)
		newServiceManager = func() (service.Manager, error) { return m, nil }
		writeDevices(t, file)
		ignoreHangup = ignoreHangupSignals
		systemLog = func(failed bool, line string) {
			_ = os.WriteFile(os.Getenv(hangupOutcomeEnv), []byte(line), 0o600)
		}
		args := strings.Fields(os.Getenv("LOCALPORT_TEST_HANGUP_ARGS"))
		var err error
		switch args[0] {
		case "set":
			err = runSet(args[1:])
		case "service":
			err = runService(args[1:])
		case "connect":
			fakeEnrol(t, deviceRef("factory.gw-01"))
			err = runConnect("test", append(args[1:], connectArgs[1:]...))
		}
		if err != nil {
			t.Fatal(err)
		}
	case hangupManager:
		if err := syscall.Kill(0, syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
	default:
		t.Skip("run by TestHangupSafeCommandsRunToTheEnd")
	}
}

// brokenOutput is a pipe whose read end is closed: a write fails with EPIPE
// and raises SIGPIPE.
func brokenOutput(t *testing.T) *os.File {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	return w
}

// hungUpTerminal is a terminal whose master is closed, as after a terminal
// session ends: a write fails with EIO.
func hungUpTerminal(t *testing.T) *os.File {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	master.Close()
	return slave
}

// service install, service uninstall and a privileged connect, run from
// a terminal session whose hangup reaches them and their service manager
// command while it runs, and with their stdout and stderr gone, run to the
// end and log that they completed. The connect record names no argument. A
// closed stdout at exec needs no case: the Go runtime opens /dev/null on a
// closed fd 0, 1 or 2 at startup (runtime.checkfds).
func TestHangupSafeCommandsRunToTheEnd(t *testing.T) {
	for args, want := range map[string]string{
		"service install":                "localport service install: completed",
		"service uninstall":              "localport service uninstall: completed",
		"connect " + hangupSentinelToken: "localport connect: completed",
	} {
		for name, output := range map[string]func(*testing.T) *os.File{"broken pipe": brokenOutput, "hung-up terminal": hungUpTerminal} {
			t.Run(args+" "+name, func(t *testing.T) {
				outcome := filepath.Join(t.TempDir(), "outcome")
				// No -test.v: the test framework writes nothing before the
				// command sets its dispositions.
				cmd := exec.Command(os.Args[0], hangupHelperRun)
				cmd.Env = append(os.Environ(),
					hangupRoleEnv+"="+hangupCommand,
					hangupOutcomeEnv+"="+outcome,
					"LOCALPORT_TEST_HANGUP_ARGS="+args,
				)
				// Its own process group, so the hangup reaches only the
				// command and its service manager command.
				cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
				out := output(t)
				cmd.Stdout, cmd.Stderr = out, out
				runErr := cmd.Run()
				out.Close()
				got, _ := os.ReadFile(outcome)
				if runErr != nil || string(got) != want {
					t.Fatalf("%s exited with %v, system log %q, want a clean exit and %q", args, runErr, got, want)
				}
			})
		}
	}
}

// syslogDialError reports no failure when no socket has a daemon behind it,
// a missing path or a stale socket, and reports any other dial failure, or
// the syslog.New error when a socket answers.
func TestSyslogDialErrorIgnoresAMissingDaemon(t *testing.T) {
	dir, err := os.MkdirTemp("", "sl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	missing := filepath.Join(dir, "missing")
	stale := filepath.Join(dir, "stale")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: stale, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	l.Close()
	notDir := filepath.Join(dir, "file")
	if err := os.WriteFile(notDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(dir, "live")
	ll, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: live, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ll.Close() })
	newErr := errors.New("Unix syslog delivery error")

	if err := syslogDialError([]string{missing, stale}, newErr); err != nil {
		t.Fatalf("no daemon: %v, want nil", err)
	}
	if err := syslogDialError([]string{missing, filepath.Join(notDir, "log")}, newErr); !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("a path under a file: %v, want ENOTDIR", err)
	}
	if err := syslogDialError([]string{missing, live}, newErr); err != newErr {
		t.Fatalf("a live socket: %v, want the syslog.New error", err)
	}
}

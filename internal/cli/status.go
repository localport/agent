package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/security"
	"github.com/localport/agent/internal/service"
	"github.com/localport/agent/internal/status"
)

// runStatus prints the device service state and, to an account that can read
// the system config (root or a member of security.AgentGroup), its devices and
// the launcher's state. The OS decides who reads the config: anyone else sees
// the service state only.
func runStatus(args []string) error {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "Usage: localport status")
		return fmt.Errorf("unexpected argument %q", args[0])
	}
	return printStatus(context.Background(), os.Stdout)
}

func printStatus(ctx context.Context, w io.Writer) error {
	if err := printServiceState(ctx, w); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		printAccount(ctx, w)
	}
	file, err := systemLocalConfig()
	if err != nil {
		return err
	}
	cfg, err := config.LoadLocal(file)
	switch {
	case errors.Is(err, fs.ErrPermission):
		fmt.Fprintf(w, "config     %s is readable by root and group %s only\n", file.Path, security.AgentGroup)
		return nil
	case errors.Is(err, fs.ErrNotExist):
		fmt.Fprintf(w, "config     none at %s\n", file.Path)
		return nil
	case err != nil:
		return err
	}
	fmt.Fprintf(w, "config     %s\n", file.Path)
	doc, docErr := readDocument(ctx)
	if docErr != nil && len(cfg.Devices) > 0 {
		fmt.Fprintf(w, "states     %s; showing the config's\n", statusUnavailable(docErr))
	}
	// Tombstones are readable only where the store is: in process, or as the
	// agent account root's status runs as.
	var store *identity.Store
	if !needsAgentChild(file) {
		store, _ = currentInvoker(false).store()
	}
	for _, d := range cfg.Devices {
		enable := make([]string, len(d.Enable))
		for i, c := range d.Enable {
			enable[i] = string(c)
		}
		fmt.Fprintf(w, "device     %s\n  state    %s\n  enable   %s\n  logins   %s\n  run_as_agent %t\n",
			d.Identity, deviceState(doc, store, d), listOrNone(enable), listOrNone(d.Logins), d.RunAsAgent)
		if len(d.PasswordLogins) > 0 {
			fmt.Fprintf(w, "  password_logins %s\n", listOrNone(d.PasswordLogins))
		}
	}
	if asAgentChild {
		// Root's status runs here as the agent account, which owns the keys.
		printFingerprints(w, cfg.Devices)
	}
	if runtime.GOOS == "windows" {
		// Only the device service may open the launcher pipe; the service
		// reports the logon state, shown per device in the dashboard.
		fmt.Fprintln(w, "launcher   session logon state: see the device in the dashboard")
		return nil
	}
	probe := probeLauncher(ctx, func(line string) { fmt.Fprintf(w, "launcher   %s\n", line) })
	fmt.Fprintf(w, "launcher   session auth %s\n", valueOrUnknown(probe.sessionAuth))
	if probe.fullDiskAccess != "" {
		fmt.Fprintf(w, "launcher   full disk access %s\n", probe.fullDiskAccess)
	}
	return nil
}

// printServiceState prints whether the device service is installed and its
// main process.
func printServiceState(ctx context.Context, w io.Writer) error {
	m, err := newServiceManager()
	if errors.Is(err, service.ErrUnsupported) {
		fmt.Fprintln(w, "service    no supported service manager")
		return nil
	}
	if err != nil {
		return err
	}
	installed, err := m.Installed()
	if err != nil {
		return err
	}
	if !installed {
		fmt.Fprintf(w, "service    %s, not installed\n", m.Name())
		return nil
	}
	pid, err := m.MainPID(ctx)
	if err != nil {
		return err
	}
	if pid == 0 {
		fmt.Fprintf(w, "service    %s, installed, not running\n", m.Name())
		return nil
	}
	fmt.Fprintf(w, "service    %s, running, pid %d\n", m.Name(), pid)
	return nil
}

// checkAccount is service.CheckAccount; tests replace it.
var checkAccount = service.CheckAccount

// printAccount prints the agent account and whether it is safe to run the
// device service as.
func printAccount(ctx context.Context, w io.Writer) {
	acct, err := checkAccount(ctx)
	if err != nil {
		fmt.Fprintf(w, "account    %s: %s\n", security.AgentGroup, userText(err))
		return
	}
	fmt.Fprintf(w, "account    %s, uid %d, ok\n", security.AgentGroup, acct.UID)
}

// deviceState is d's state from the service's document when it reports d,
// else from disk: removed (a tombstone and no credential, when store is
// readable), paused, or configured.
func deviceState(doc *status.Document, store *identity.Store, d config.LocalDevice) string {
	if doc != nil {
		if row := rowOf(doc, d.Identity); row != nil {
			return describeRow(row)
		}
	}
	if store != nil {
		if f := storeFact(store, d.Identity); f.Removed != "" {
			return describeRow(&status.Device{State: status.StateRemoved, Code: f.Removed})
		}
	}
	if d.Paused {
		return describeRow(&status.Device{State: status.StatePaused})
	}
	return "configured"
}

// describeRow names a state for a person, with its remedy.
func describeRow(row *status.Device) string {
	if row == nil {
		return "not reported by the device service"
	}
	code := security.SanitizeDisplay(row.Code)
	retry := ""
	if row.NextRetry != nil {
		retry = ", next try " + row.NextRetry.Local().Format(time.TimeOnly)
	}
	switch row.State {
	case status.StateRunning:
		return "running"
	case status.StateConnecting:
		return "connecting"
	case status.StatePaused:
		return "paused; resume it " + elevatedCommand("up")
	case status.StateDraining:
		return "disconnected by an admin, ending its sessions"
	case status.StateDisconnected:
		return "disconnected by an admin; it reconnects when an admin reconnects it in the dashboard" + retry
	case status.StateWaiting:
		return "waiting: refused with " + code + "; it retries on its own" + retry
	case status.StateParked:
		return "stopped: refused with " + code + "; fix the cause, then retry " + elevatedCommand("up")
	case status.StateRemoved:
		return "removed: refused with " + code + " (removed or enrolled again); enrol it again " + elevatedCommand("up <join-token>")
	}
	return security.SanitizeDisplay(row.State)
}

// statusUnavailable explains a failed status read.
func statusUnavailable(err error) string {
	switch {
	case errors.Is(err, status.ErrNoDocument):
		return "the device service is not running, or this account may not read its status (root or group " + security.AgentGroup + "; an elevated prompt on Windows)"
	case errors.Is(err, launcher.ErrUnavailable):
		return "status unavailable: the session launcher is not running"
	}
	return "status unavailable: " + userText(err)
}

func listOrNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ",")
}

func valueOrUnknown(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

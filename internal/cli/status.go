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
		return errExtraArgument.With(nil, fmt.Sprintf("%q", security.SanitizeDisplay(args[0])))
	}
	return printStatus(context.Background(), os.Stdout)
}

func printStatus(ctx context.Context, w io.Writer) error {
	// Root's status prints these itself (runRootStatus): the account check
	// reads /etc/shadow, which the agent account cannot.
	if !asAgentChild {
		if err := printStatusHeader(ctx, w); err != nil {
			return err
		}
	}
	return printStatusDevices(ctx, w)
}

// printStatusHeader prints the service state and, on Linux and macOS, the
// agent account's check.
func printStatusHeader(ctx context.Context, w io.Writer) error {
	if err := printServiceState(ctx, w); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		printAccount(ctx, w)
	}
	return nil
}

// runRootStatus is status for root on the system layout: root prints the
// header, then runs the rest as the agent account, which owns the device
// keys (printStatusDevices in the agent child).
func runRootStatus(args []string) error {
	if len(args) > 1 {
		return runAsAgentAccount(args, os.Stdin, os.Stdout)
	}
	if err := printStatusHeader(context.Background(), os.Stdout); err != nil {
		return err
	}
	return runAsAgentAccount(args, os.Stdin, os.Stdout)
}

// printStatusDevices prints the config, its devices and the launcher's state
// to an account that can read the system config.
func printStatusDevices(ctx context.Context, w io.Writer) error {
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
	// agent account root's status runs as. An unprivileged reader of the
	// system config has its own store, which holds none of these devices.
	var store *identity.Store
	if who := currentInvoker(false); !needsAgentChild(file) && who.privileged {
		store, _ = who.store()
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

// printServiceState prints whether the device service is installed, and its main process.
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
	fmt.Fprintf(w, "service    %s, running, pid %d%s\n", m.Name(), pid, standbyNote(pid))
	return nil
}

// standbyNote is ", waiting: ..." when the running service with main process
// servicePID stands by because another process holds the run lock
// (holdServiceRunLock), and "" otherwise or when this account cannot tell.
// The holder's PID counts only while the lock is held, as a holder that died
// leaves its PID behind.
func standbyNote(servicePID int) string {
	file, err := systemLocalConfig()
	if err != nil {
		return ""
	}
	if held, err := config.RunLockHeld(file); err != nil || !held {
		return ""
	}
	holder, err := config.RunLockHolder(file)
	if err != nil || holder == servicePID {
		return ""
	}
	if holder == 0 {
		return ", waiting: another process serves the devices"
	}
	return fmt.Sprintf(", waiting: a foreground run (pid %d) serves the devices", holder)
}

// checkAccount is service.CheckAccount; tests replace it.
var checkAccount = service.CheckAccount

// printAccount prints the agent account and whether it is safe to run the
// device service as.
func printAccount(ctx context.Context, w io.Writer) {
	acct, err := checkAccount(ctx)
	if errors.Is(err, service.ErrPasswordUnchecked) {
		fmt.Fprintf(w, "account    %s, uid %d, ok except the password, which only root can check\n", security.AgentGroup, acct.UID)
		return
	}
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
	refusal := "refused"
	if code := security.SanitizeDisplay(row.Code); code != "" {
		refusal = "refused with " + code
	}
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
		return "disconnected by an admin until an admin reconnects it in the dashboard" + retry
	case status.StateWaiting:
		return "waiting: " + refusal + "; it retries on its own" + retry
	case status.StateParked:
		return "stopped: " + refusal + "; fix the cause, then retry " + elevatedCommand("up")
	case status.StateRemoved:
		return "removed: " + refusal + " (removed or enrolled again); enrol it again " + elevatedCommand("up <join-token>")
	}
	return security.SanitizeDisplay(row.State)
}

// statusReaders names who may read the device status.
const statusReaders = "root or group " + security.AgentGroup + "; an elevated prompt on Windows"

// statusUnavailable explains a failed status read.
func statusUnavailable(err error) string {
	switch {
	case errors.Is(err, status.ErrNoDocument):
		return "the device service is not running, or this account may not read its status (" + statusReaders + ")"
	case errors.Is(err, launcher.ErrStatusDenied):
		return "this account may not read the device status (" + statusReaders + ")"
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

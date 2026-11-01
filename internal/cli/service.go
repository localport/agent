package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/service"
)

// runService runs `localport service install` and
// `localport service uninstall [--purge]`. Both run to the end through a
// hangup of the terminal they run in, which restarting or stopping the
// service may cause, and as root record their outcome in the system log.
func runService(args []string) (err error) {
	ignoreHangup()
	if len(args) == 0 || (args[0] != "install" && args[0] != "uninstall") {
		usageService()
		return errors.New("unknown service command; use install or uninstall")
	}
	sub := args[0]
	var who invoker
	defer func() {
		if who.privileged {
			logOutcome(append([]string{"service"}, args...), err, true)
		}
	}()
	fs := flag.NewFlagSet("service "+sub, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var purge *bool
	if sub == "uninstall" {
		purge = fs.Bool("purge", false, "also delete the machine-wide local config, the device credentials and the recording spool")
	}
	fs.Usage = usageService
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		usageService()
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	who = currentInvoker(false)
	if !who.privileged {
		return fmt.Errorf("service %s needs root: run it with sudo (from an elevated prompt on Windows)", sub)
	}
	if sub == "install" {
		return installService(who)
	}
	return uninstallService(who, *purge)
}

// installService installs or rewrites the device service for the devices
// already in the local config, and starts it. It spends no token, so it
// recovers from an install that failed after connect enrolled.
func installService(who invoker) error {
	file, err := who.localConfigFile()
	if err != nil {
		return err
	}
	local, err := loadLocalOrEmpty(file)
	if err != nil {
		return err
	}
	if len(local.Devices) == 0 {
		return fmt.Errorf("%w: %s lists no device; enrol one with: sudo localport connect <join-token>", errNoDevice, file.Path)
	}
	if needsAgentChild(file) {
		// Before prepareService, whose run.lock check needs the account's
		// group; a root-run install is converted here.
		m, exe := platformManager()
		if err := prepareSystemLayout(context.Background(), file, m, exe); err != nil {
			return err
		}
	}
	svc, err := prepareService(file)
	if err != nil {
		return err
	}
	if err := svc.install(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "  installed and started %s for the devices in %s\n", svc.manager.Name(), file.Path)
	return nil
}

// errNoDevice refuses to install a service with nothing to run.
var errNoDevice = errcode.New(errcode.NoDevice)

// purgeRunLockWait bounds how long uninstall --purge waits for the stopped
// service to release run.lock.
const purgeRunLockWait = 30 * time.Second

func uninstallService(who invoker, purge bool) error {
	m, err := newServiceManager()
	runLockWait := time.Duration(0)
	switch {
	case errors.Is(err, service.ErrUnsupported):
		fmt.Fprintf(os.Stderr, "  %v\n", err)
	case err != nil:
		return err
	default:
		switch err := m.Uninstall(context.Background()); {
		case errors.Is(err, service.ErrNotInstalled):
			fmt.Fprintf(os.Stderr, "  %v\n", err)
		case err != nil:
			return err
		default:
			fmt.Fprintf(os.Stderr, "  stopped and removed %s\n", m.Name())
			runLockWait = purgeRunLockWait
		}
	}
	if !purge {
		return nil
	}
	return purgeSystemDevices(who, m, runLockWait)
}

// purgeSystemDevices deletes the machine-wide local config, the device
// credentials of the system store and the recording spool; machine and
// sign-in credentials in the same store stay. It refuses while a device
// service carrying the marker is still installed or, on Windows, marked for
// deletion (m is nil without a supported service manager), and while
// another process holds run.lock after runLockWait. It holds run.lock, then
// the config's lock, through the deletion, so no run serves and no set or
// connect writes meanwhile. The lock files and the directory stay, so a
// concurrent command never locks an unlinked file; a missing directory is
// left missing.
func purgeSystemDevices(who invoker, m service.Manager, runLockWait time.Duration) (retErr error) {
	file, err := who.localConfigFile()
	if err != nil {
		return err
	}
	// As root on the system layout the agent account deletes the store's
	// contents (runAsAgentAccount); root only removes the config.
	viaChild := needsAgentChild(file)
	var store *identity.Store
	if !viaChild {
		if store, err = who.store(); err != nil {
			return err
		}
	}
	const stillValid = "  the device certificates stay valid until the devices are removed in the dashboard"
	dir := filepath.Dir(file.Path)
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "  nothing to delete: %s does not exist\n%s\n", dir, stillValid)
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect %s: %w", dir, err)
	}
	if m != nil {
		installed, err := m.Installed()
		if err != nil {
			return err
		}
		if installed {
			return fmt.Errorf("%w (%s); remove it and the devices together with: sudo localport service uninstall --purge", errServiceInstalled, m.Name())
		}
	}
	releaseRun, err := config.LockRun(file, runLockWait)
	if errors.Is(err, config.ErrRunLocked) {
		return fmt.Errorf("%w; stop the localport run or connect --foreground serving the devices, then run the command again", err)
	}
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, releaseRun()) }()
	unlock, err := config.LockLocal(file)
	if err != nil {
		return err
	}
	defer unlock()
	if err := os.Remove(file.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", file.Path, err)
	}
	fmt.Fprintf(os.Stderr, "  deleted %s\n", file.Path)
	if err := purgeDeviceStore(dir, viaChild, store); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "  %s, %s and %s remain\n%s\n", file.LockPath(), file.RunLockPath(), dir, stillValid)
	return nil
}

// purgeDeviceStore deletes the device credentials and the spool: in the
// agent-account child when viaChild (nothing to do without an identity
// directory), otherwise in store.
func purgeDeviceStore(dir string, viaChild bool, store *identity.Store) error {
	if !viaChild {
		return purgeStore(store)
	}
	idDir := filepath.Join(dir, "identity")
	if _, err := os.Lstat(idDir); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect %s: %w", idDir, err)
	}
	return runAsAgentAccount([]string{"purge"}, nil, os.Stdout)
}

func usageService() {
	fmt.Fprint(os.Stderr, `Usage: localport service install
       localport service uninstall [--purge]

  Both need root: run them with sudo (from an elevated prompt on Windows).

  install installs or rewrites the device service (systemd
  localport-device.service, launchd io.localport.device, Windows service
  localport-device) for the devices already in the machine-wide local config,
  and starts it. It needs no join token, and is refused when the config lists
  no device, when someone other than root (Administrators) could replace the
  localport binary, or while a manual localport run holds the devices.

  uninstall stops and removes the device service. A service definition
  localport did not write is refused. With no service installed it says so
  and exits 0. The devices' credentials and local config stay, so connect or
  the service can use them again, unless --purge deletes them.

  --purge waits up to 30 s for the stopped service to release run.lock and
  is refused while another localport run holds it. It deletes agent.yaml,
  the device credentials under identity/ and the recording spool
  recordings/, with the recordings not yet uploaded. Machine credentials
  from setup and sign-in credentials stay, as do the lock files
  agent.yaml.lock and run.lock and the directory. --purge does not revoke
  the devices: their certificates stay valid until the devices are removed
  in the dashboard.

Flags (uninstall):
  --purge   also delete the machine-wide local config, the device credentials
            and the recording spool
`)
}

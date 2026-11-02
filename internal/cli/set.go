package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/identity"
)

// runSet edits one enrolled device's settings in the local config and, as
// root or an elevated Administrator, reloads the installed device service so
// they apply (Manager.Reload: the agent applies the changed devices only on
// Unix; the Windows service restarts). Besides a re-enrolment with connect,
// it is the way to change what an enrolled device allows. As root it records
// its outcome in the system log.
func runSet(args []string) (err error) {
	var who invoker
	defer func() {
		if who.privileged {
			logOutcome(append([]string{"set"}, args...), err, true)
		}
	}()
	fs := flag.NewFlagSet("set", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	device := addDeviceFlags(fs)
	fs.Usage = func() { usageSet(fs) }

	name, rest := "", args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, rest = args[0], args[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if name == "" {
		fs.Usage()
		return fmt.Errorf("name the device to change")
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	who = currentInvoker(false)
	file, err := who.localConfigFile()
	if err != nil {
		return err
	}
	ref, err := updateDevice(file, fs, device, who, name)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "  updated %s in %s\n", ref, file.Path)
	if !who.privileged {
		fmt.Fprintf(os.Stderr, "  restart `localport run` to apply it\n")
		return nil
	}
	reloaded, err := reloadDeviceService()
	switch {
	case err != nil:
		// A service installed by an older localport has no reload; installing
		// it again converts it and applies the saved settings.
		return fmt.Errorf("the settings are saved, but the device service did not reload: %w\n  apply them with: %s", err, serviceInstallCommand)
	case reloaded:
		fmt.Fprintf(os.Stderr, "  reloaded the device service\n")
	default:
		fmt.Fprintf(os.Stderr, "  no device service is installed, so nothing was reloaded; restart `localport run` to apply it\n")
	}
	return nil
}

// updateDevice applies the flags to one device's entry under the local
// config's lock, released before the service reloads.
func updateDevice(file config.LocalConfigFile, fs *flag.FlagSet, device *deviceFlags, who invoker, name string) (identity.Ref, error) {
	unlock, err := config.LockLocal(file)
	if err != nil {
		return identity.Ref{}, err
	}
	defer unlock()
	local, err := config.LoadLocal(file)
	if err != nil {
		return identity.Ref{}, err
	}
	i, err := findDevice(local.Devices, name)
	if err != nil {
		return identity.Ref{}, err
	}
	d := local.Devices[i]
	if err := device.apply(fs, &d, who); err != nil {
		return identity.Ref{}, err
	}
	local.Devices[i] = d
	if err := config.WriteLocal(file, local, d.Identity); err != nil {
		return identity.Ref{}, err
	}
	return d.Identity, nil
}

// reloadDeviceService reloads the device service when one carrying the
// marker is installed, reporting whether it did.
func reloadDeviceService() (bool, error) {
	m, installed, err := installedDeviceService()
	if err != nil || !installed {
		return false, err
	}
	if err := m.Reload(context.Background()); err != nil {
		return false, err
	}
	return true, nil
}

// findDevice locates a device by its full identity, its
// <tunnelIdentifier>.<prefix> form, or its prefix alone when that is unique.
func findDevice(devices []config.LocalDevice, name string) (int, error) {
	found := -1
	for i, d := range devices {
		_, prefix, _ := strings.Cut(d.Identity.Identity, ".")
		if name != d.Identity.String() && name != d.Identity.Identity && name != prefix {
			continue
		}
		if found >= 0 {
			return -1, fmt.Errorf("%q names more than one device; use the full identity from the local config", name)
		}
		found = i
	}
	if found < 0 {
		return -1, fmt.Errorf("no enrolled device %q in the local config", name)
	}
	return found, nil
}

func usageSet(fs *flag.FlagSet) {
	fmt.Fprint(os.Stderr, `Usage: localport set <device> [--enable LIST] [--logins LIST] [--files-root DIR]
                     [--rdp[=HOST:PORT]] [--vnc[=HOST:PORT]] [--host HOST] [--allow-ports LIST]

  Change what an enrolled device allows, in the local config. <device> is its
  identity, <fleet>.<device>, or the device name when unique. Only the flags
  given change; a list flag replaces the whole list. As root (Administrator on
  Windows) set reloads the installed device service, which applies the
  change: only the changed device restarts and its open sessions end
  (Windows restarts the service). A device run with localport run applies it
  when restarted.

Flags:
`)
	fs.PrintDefaults()
}

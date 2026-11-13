package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/identity"
)

// runSet edits one enrolled device's settings in the local config and, as
// root or an elevated Administrator, reloads the installed device service so
// they apply (Manager.Reload: SIGHUP on Unix, a parameter change on Windows;
// the agent restarts only the changed devices). Besides a re-enrolment with connect,
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
	// set's own flags: they act on the device's pinned keys, not its config,
	// so they are not deviceFlags flags connect would share.
	resetRDPPin := fs.Bool("rdp-reset-pin", false, "forget the RDP server certificate key trusted for this device; the next connection asks to trust it again")
	resetVNCPin := fs.Bool("vnc-reset-pin", false, "forget the VNC server key trusted for this device; the next connection asks to trust the key again")
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
	var resetKinds []string
	if *resetRDPPin {
		resetKinds = append(resetKinds, "rdp")
	}
	if *resetVNCPin {
		resetKinds = append(resetKinds, "vnc")
	}
	configFlags := false
	fs.Visit(func(f *flag.Flag) {
		configFlags = configFlags || (f.Name != "rdp-reset-pin" && f.Name != "vnc-reset-pin")
	})
	if len(resetKinds) > 0 && !configFlags {
		// A pin reset alone changes no setting: no config write, no reload.
		ref, err := lookupDevice(file, name)
		if err != nil {
			return err
		}
		return resetPins(file, who, ref, resetKinds)
	}
	ref, err := updateDevice(file, fs, device, who, name)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "  updated %s in %s\n", ref, file.Path)
	applyErr := applySettings(who)
	if len(resetKinds) > 0 {
		// After the config lock is released (the two locks never nest), and
		// after the saved settings were applied, so a failed reset leaves no
		// setting saved but unapplied.
		return errors.Join(applyErr, resetPins(file, who, ref, resetKinds))
	}
	return applyErr
}

// applySettings applies saved settings: as root it reloads the installed
// device service, otherwise it tells the user to restart `localport run`.
func applySettings(who invoker) error {
	if !who.privileged {
		fmt.Fprintf(os.Stderr, "  restart `localport run` to apply it\n")
		return nil
	}
	reloaded, err := reloadDeviceService()
	switch {
	case err != nil:
		// Installing the service again applies the saved settings.
		return errcode.WithRemedy(errcode.New(errcode.SettingsNotApplied).With(err, ""), "apply them with: "+serviceInstallCommand)
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

// lookupDevice names the enrolled device name refers to, from the local
// config, which it only reads.
func lookupDevice(file config.LocalConfigFile, name string) (identity.Ref, error) {
	local, err := config.LoadLocal(file)
	if err != nil {
		return identity.Ref{}, err
	}
	i, err := findDevice(local.Devices, name)
	if err != nil {
		return identity.Ref{}, err
	}
	return local.Devices[i].Identity, nil
}

// runPinsChild is runAsAgentAccount; tests record the dispatch.
var runPinsChild = runAsAgentAccount

// resetPins resets the pins of kinds for ref: as root on the system layout
// in the set-pins agent child, which owns the store, otherwise in process.
func resetPins(file config.LocalConfigFile, who invoker, ref identity.Ref, kinds []string) error {
	if needsAgentChild(file) {
		return runPinsChild(append([]string{"set-pins", ref.String()}, kinds...), nil, os.Stdout)
	}
	return resetDesktopPins(who, ref, kinds)
}

// desktopKeyNames names each desktop kind's pinned key in set's output.
var desktopKeyNames = map[string]string{"rdp": "RDP server certificate key", "vnc": "VNC server key"}

// resetDesktopPins forgets the server keys of kinds pinned for ref in the
// credential store beside the invoker's config. Open sessions continue; the
// next connection asks to trust the server's key again. An unreadable pin
// file is removed by the first reset, which leaves nothing for the rest.
func resetDesktopPins(who invoker, ref identity.Ref, kinds []string) error {
	store, err := who.store()
	if err != nil {
		return err
	}
	pins, err := store.DesktopPins(ref)
	if err != nil {
		return err
	}
	for _, kind := range kinds {
		name := desktopKeyNames[kind]
		result, err := pins.Reset(context.Background(), kind)
		if err != nil {
			return errcode.New(errcode.PinResetFailed).With(err, fmt.Sprintf("the %s of %s", name, ref))
		}
		switch result {
		case identity.ResetForgot:
			fmt.Fprintf(os.Stderr, "  forgot the %s trusted for %s; the next connection asks to trust the key\n", name, ref)
		case identity.ResetDiscarded:
			fmt.Fprintf(os.Stderr, "  removed the unreadable desktop_pins.json of %s with every server key it held; the next connection asks to trust the key\n", ref)
			return nil
		default:
			fmt.Fprintf(os.Stderr, "  no %s was trusted for %s\n", name, ref)
		}
	}
	return nil
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
			return -1, errcode.New(errcode.DeviceAmbiguous).With(nil, fmt.Sprintf("%q; use the full identity from the local config", name))
		}
		found = i
	}
	if found < 0 {
		return -1, errcode.New(errcode.NoDevice).With(nil, fmt.Sprintf("%q in the local config", name))
	}
	return found, nil
}

func usageSet(fs *flag.FlagSet) {
	fmt.Fprint(os.Stderr, `Usage: localport set <device> [--enable LIST] [--logins LIST] [--files-root DIR]
                     [--rdp[=HOST:PORT]] [--vnc[=HOST:PORT]] [--host HOST] [--allow-ports LIST]
                     [--rdp-reset-pin] [--vnc-reset-pin]

  Change what an enrolled device allows, in the local config. <device> is its
  identity, <fleet>.<device>, or the device name when unique. Only the flags
  given change; a list flag replaces the whole list. As root (Administrator on
  Windows) set reloads the installed device service, which applies the
  change: only the changed device restarts and its open sessions end. A
  device run with localport run applies it
  when restarted.

  --rdp-reset-pin and --vnc-reset-pin forget the RDP server certificate key or
  the VNC server key trusted on the device's first browser connection, after
  the server's key changed on purpose; alone they change no setting and reload
  nothing. An unreadable desktop_pins.json is removed with every key it held.

Flags:
`)
	fs.PrintDefaults()
}

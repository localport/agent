//go:build linux

package service

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// Default is the manager of the init system that booted the host: systemd,
// OpenRC or OpenWrt procd; ErrUnsupported for any other.
func Default() (Manager, error) {
	// sd_booted(3): this directory exists only when systemd booted the system.
	if ok, err := exists("/run/systemd/system"); err != nil {
		return nil, fmt.Errorf("detect systemd: %w", err)
	} else if ok {
		// Merged-/usr systems have both; older Debian ships only /bin/systemctl.
		systemctl, ok := firstExisting("/usr/bin/systemctl", "/bin/systemctl")
		if !ok {
			return nil, fmt.Errorf("%w: systemd runs, but neither /usr/bin/systemctl nor /bin/systemctl exists", ErrUnsupported)
		}
		return systemd{unitPath: SystemdUnitPath, systemctl: systemctl, run: execRun}, nil
	}
	// openrc-run tests this file to decide that OpenRC booted the system.
	if ok, err := exists("/run/openrc/softlevel"); err != nil {
		return nil, fmt.Errorf("detect OpenRC: %w", err)
	} else if ok {
		rcService, ok1 := firstExisting("/sbin/rc-service", "/usr/sbin/rc-service")
		rcUpdate, ok2 := firstExisting("/sbin/rc-update", "/usr/sbin/rc-update")
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("%w: OpenRC runs, but rc-service or rc-update is missing", ErrUnsupported)
		}
		return openrc{initDir: openrcInitDir, rcService: rcService, rcUpdate: rcUpdate, logDir: openrcAgentLogDir, account: LookupAccount, run: execRun}, nil
	}
	if comm, err := os.ReadFile("/proc/1/comm"); err == nil && string(bytes.TrimSpace(comm)) == "procd" {
		ubus, ok := firstExisting("/bin/ubus", "/usr/bin/ubus", "/sbin/ubus")
		if !ok {
			return nil, fmt.Errorf("%w: procd runs, but ubus is missing", ErrUnsupported)
		}
		return procd{initDir: procdInitDir, ubus: ubus, run: execRun}, nil
	}
	return nil, ErrUnsupported
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func firstExisting(paths ...string) (string, bool) {
	for _, p := range paths {
		if ok, _ := exists(p); ok {
			return p, true
		}
	}
	return "", false
}

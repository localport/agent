//go:build linux

package service

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// Default is the systemd manager, or ErrUnsupported when systemd is not the
// init system.
func Default() (Manager, error) {
	// sd_booted(3): this directory exists only when systemd booted the system.
	_, err := os.Stat("/run/systemd/system")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrUnsupported
	}
	if err != nil {
		return nil, fmt.Errorf("detect systemd: %w", err)
	}
	// Merged-/usr systems have both; older Debian ships only /bin/systemctl.
	for _, systemctl := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		if _, err := os.Stat(systemctl); err == nil {
			return systemd{unitPath: SystemdUnitPath, systemctl: systemctl, run: execRun}, nil
		}
	}
	return nil, fmt.Errorf("%w: systemd runs, but neither /usr/bin/systemctl nor /bin/systemctl exists", ErrUnsupported)
}

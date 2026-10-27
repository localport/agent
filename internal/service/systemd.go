package service

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SystemdUnit is the device service's systemd unit name.
const SystemdUnit = "localport-device.service"

// SystemdUnitPath is where the unit is installed.
const SystemdUnitPath = "/etc/systemd/system/" + SystemdUnit

// systemd manages the device service as a systemd unit.
type systemd struct {
	unitPath string
	// systemctl is the absolute path of systemctl.
	systemctl string
	run       runner
}

func (s systemd) Name() string { return SystemdUnit }

// Check refuses a unit file without Marker, and a unit systemd loads from
// another fragment, a /dev/null mask included. Drop-ins (systemctl edit
// overrides, type-level service.d/ files) are accepted and returned: install
// never writes one, and only root can.
func (s systemd) Check() (dropIns []string, err error) {
	if _, err := owned(s.unitPath); err != nil {
		return nil, err
	}
	out, err := s.run(context.Background(), s.systemctl, "show", "-p", "FragmentPath,DropInPaths", SystemdUnit)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(out, "\n") {
		key, value, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch {
		case key == "FragmentPath" && value != "" && value != s.unitPath:
			return nil, fmt.Errorf("%w: systemd loads %s from %s; remove or unmask that unit and run systemctl daemon-reload, then run the command again", ErrForeignUnit, SystemdUnit, value)
		case key == "DropInPaths":
			dropIns = strings.Fields(value)
		}
	}
	return dropIns, nil
}

func (s systemd) Installed() (bool, error) { return owned(s.unitPath) }

// MainPID reads MainPID and ActiveState; a unit in any state but active
// (activating, deactivating, auto-restart, failed, inactive) reports 0.
func (s systemd) MainPID(ctx context.Context) (int, error) {
	out, err := s.run(ctx, s.systemctl, "show", "-p", "MainPID,ActiveState", SystemdUnit)
	if err != nil {
		return 0, err
	}
	pid, active := 0, false
	for _, line := range strings.Split(out, "\n") {
		key, value, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch key {
		case "ActiveState":
			active = value == "active"
		case "MainPID":
			if pid, err = strconv.Atoi(value); err != nil {
				return 0, fmt.Errorf("systemctl show %s: MainPID %q: %w", SystemdUnit, value, err)
			}
		}
	}
	if !active {
		return 0, nil
	}
	return pid, nil
}

func (s systemd) Install(ctx context.Context, exe string) error {
	unit, err := systemdUnitFile(exe)
	if err != nil {
		return err
	}
	if err := writeOwned(s.unitPath, unit); err != nil {
		return err
	}
	return s.sequence(ctx,
		[]string{"daemon-reload"},
		[]string{"enable", SystemdUnit},
		// restart starts a stopped unit and restarts a running one, which a
		// re-enrolment needs to load the new credential.
		[]string{"restart", SystemdUnit},
	)
}

func (s systemd) Restart(ctx context.Context) error {
	_, err := s.run(ctx, s.systemctl, "restart", SystemdUnit)
	return err
}

func (s systemd) Uninstall(ctx context.Context) error {
	exists, err := owned(s.unitPath)
	if err != nil {
		return err
	}
	if !exists {
		return ErrNotInstalled
	}
	if _, err := s.run(ctx, s.systemctl, "disable", "--now", SystemdUnit); err != nil {
		return err
	}
	if err := removeOwned(s.unitPath); err != nil {
		return err
	}
	_, err = s.run(ctx, s.systemctl, "daemon-reload")
	return err
}

func (s systemd) sequence(ctx context.Context, steps ...[]string) error {
	for _, args := range steps {
		if _, err := s.run(ctx, s.systemctl, args...); err != nil {
			return err
		}
	}
	return nil
}

// systemdSafePath is what ExecStart carries unquoted: no whitespace, quotes,
// backslashes, or the % and $ systemd expands.
var systemdSafePath = regexp.MustCompile(`^/[A-Za-z0-9._+@/-]+$`)

// systemdUnitFile is the unit running exe. Terminal and files sessions start
// login shells inside the service's sandbox, so every directive that would
// confine those shells is left out, each named below with its reason.
func systemdUnitFile(exe string) ([]byte, error) {
	if !systemdSafePath.MatchString(exe) {
		return nil, fmt.Errorf("%w: %q (systemd needs an absolute path of letters, digits and ._+@/-)", ErrUnsafeExecutable, exe)
	}
	return fmt.Appendf(nil, `# %s
# Configure the devices with localport set; /etc/localport-device/agent.yaml
# holds their settings and /etc/localport-device/identity their private keys,
# so keep that directory out of backups and configuration management.

[Unit]
Description=Localport fleet device agent
Documentation=https://localport.io/docs
After=network-online.target
Wants=network-online.target

[Service]
# root: sessions start login shells as the device's logins.
User=root
ExecStart=%s run --service
Restart=always
RestartSec=5
# The agent ends its terminal sessions itself on stop, so systemd signals only it.
KillMode=process

# A core dump would contain the device's private keys.
LimitCORE=0
# Required: sudo and other setuid programs in a session must work.
NoNewPrivileges=no
# Left out, because a session's shell inherits each of them:
#   ProtectSystem, ProtectHome, ReadWritePaths: a read-only /usr, /etc or /home
#     would stop package upgrades and file edits in a session.
#   PrivateTmp, PrivateDevices: a session must see the machine's /tmp and its
#     serial and USB devices.
#   CapabilityBoundingSet, RestrictSUIDSGID, SystemCallFilter, RestrictNamespaces,
#     MemoryDenyWriteExecute: they would break sudo, containers and JIT runtimes
#     started from a session.
#   UMask: the agent keeps systemd's default 0022, and login(1) sets a
#     terminal session's umask from login.defs or PAM where it supports that.

[Install]
WantedBy=multi-user.target
`, Marker, exe), nil
}

package service

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/localport/agent/internal/agentaccount"
	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/security"
)

// SystemdUnit is the device service's systemd unit name.
const SystemdUnit = "localport-device.service"

// SystemdUnitPath is where the unit is installed.
const SystemdUnitPath = "/etc/systemd/system/" + SystemdUnit

// The session launcher's units, installed beside SystemdUnit: the socket
// systemd binds and the root service it starts on the first connection.
const (
	SystemdLauncherSocket  = "localport-session.socket"
	SystemdLauncherService = "localport-session.service"
)

// systemdDeviceDir is the device directory the agent unit names.
var systemdDeviceDir = filepath.Join("/etc", security.DeviceDirName)

// systemd manages the device service and the session launcher as systemd
// units. unitPath is the agent unit; the launcher units sit beside it.
type systemd struct {
	unitPath string
	// systemctl is the absolute path of systemctl.
	systemctl string
	run       runner
}

func (s systemd) Name() string { return SystemdUnit }

// units are the unit names this manager writes and the path of each.
func (s systemd) units() []struct{ name, path string } {
	dir := filepath.Dir(s.unitPath)
	return []struct{ name, path string }{
		{SystemdUnit, s.unitPath},
		{SystemdLauncherSocket, filepath.Join(dir, SystemdLauncherSocket)},
		{SystemdLauncherService, filepath.Join(dir, SystemdLauncherService)},
	}
}

func (s systemd) paths() []string {
	var paths []string
	for _, u := range s.units() {
		paths = append(paths, u.path)
	}
	return paths
}

// Check refuses a unit file without Marker, and a unit systemd loads from
// another fragment, a /dev/null mask included. Drop-ins (systemctl edit
// overrides, type-level service.d/ files) are accepted and returned: install
// never writes one, and only root can.
func (s systemd) Check() (dropIns []string, err error) {
	if err := checkOwned(s.paths()...); err != nil {
		return nil, err
	}
	for _, u := range s.units() {
		out, err := s.run(context.Background(), s.systemctl, "show", "-p", "FragmentPath,DropInPaths", u.name)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(out, "\n") {
			key, value, _ := strings.Cut(strings.TrimSpace(line), "=")
			switch {
			case key == "FragmentPath" && value != "" && value != u.path:
				return nil, ErrForeignUnit.With(nil, fmt.Sprintf("systemd loads %s from %s; remove or unmask that unit and run systemctl daemon-reload, then run the command again", u.name, value))
			case key == "DropInPaths":
				dropIns = append(dropIns, strings.Fields(value)...)
			}
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
				return 0, errManager.With(err, fmt.Sprintf("systemctl show %s: MainPID %q", SystemdUnit, value))
			}
		}
	}
	if !active {
		return 0, nil
	}
	return pid, nil
}

// Install writes the three units, enables the launcher socket and the agent,
// and (re)starts them. The launcher is restarted only when it is running
// (try-restart), so an upgraded binary takes effect; its sessions survive
// (KillMode=process).
func (s systemd) Install(ctx context.Context, exe string) error {
	files, err := systemdUnits(exe)
	if err != nil {
		return err
	}
	if err := checkOwned(s.paths()...); err != nil {
		return err
	}
	for _, u := range s.units() {
		if err := writeOwned(u.path, files[u.name]); err != nil {
			return err
		}
	}
	return s.sequence(ctx,
		[]string{"daemon-reload"},
		[]string{"enable", "--now", SystemdLauncherSocket},
		[]string{"try-restart", SystemdLauncherService},
		[]string{"enable", SystemdUnit},
		// restart starts a stopped unit and restarts a running one, so a
		// reinstall or an upgrade runs the new definition and binary.
		[]string{"restart", SystemdUnit},
	)
}

func (s systemd) Restart(ctx context.Context) error {
	_, err := s.run(ctx, s.systemctl, "restart", SystemdUnit)
	return err
}

// Reload makes the agent re-read its config (ExecReload sends SIGHUP).
func (s systemd) Reload(ctx context.Context) error {
	_, err := s.run(ctx, s.systemctl, "reload", SystemdUnit)
	return err
}

// Uninstall stops and disables the agent and the launcher, and removes the
// three units. Running sessions end with the agent: their helpers read the
// end of the channel.
func (s systemd) Uninstall(ctx context.Context) error {
	if err := checkOwned(s.paths()...); err != nil {
		return err
	}
	exists, err := owned(s.unitPath)
	if err != nil {
		return err
	}
	if !exists {
		return ErrNotInstalled
	}
	if err := s.sequence(ctx,
		[]string{"disable", "--now", SystemdUnit},
		[]string{"disable", "--now", SystemdLauncherSocket},
		[]string{"stop", SystemdLauncherService},
	); err != nil {
		return err
	}
	for _, u := range s.units() {
		if err := removeOwned(u.path); err != nil && !errors.Is(err, ErrNotInstalled) {
			return err
		}
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

// systemdUnits are the three unit files for the agent at exe and the
// launcher beside it (SessionExecutable), by unit name.
func systemdUnits(exe string) (map[string][]byte, error) {
	if !systemdSafePath.MatchString(exe) {
		return nil, ErrUnsafeExecutable.With(nil, fmt.Sprintf("%q (systemd needs an absolute path of letters, digits and ._+@/-)", exe))
	}
	session := SessionExecutable(exe)
	identityDir := filepath.Join(systemdDeviceDir, "identity")
	runLock := filepath.Join(systemdDeviceDir, "run.lock")
	return map[string][]byte{
		SystemdUnit: fmt.Appendf(nil, `# %[1]s
# Configure the devices with localport set; %[2]s/agent.yaml
# holds their settings and %[3]s their private keys,
# so keep that directory out of backups and configuration management.

[Unit]
Description=Localport fleet device agent
Documentation=https://localport.io/docs
After=network-online.target %[6]s
Wants=network-online.target %[6]s

[Service]
User=%[7]s
Group=%[7]s
ExecStart=%[4]s run --service
# localport set changes the config and reloads; the agent applies the
# changed devices only.
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
TimeoutStopSec=%[8]d
UMask=0077

# A core dump would contain the device's private keys.
LimitCORE=0
# The agent starts no session itself: the root launcher behind
# %[6]s does, outside this sandbox.
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
# "-": a path that does not exist yet does not fail the start.
ReadWritePaths=-%[3]s -%[5]s
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateIPC=yes
RemoveIPC=yes
ProtectProc=invisible
ProcSubset=pid
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
`, Marker, systemdDeviceDir, identityDir, exe, runLock, SystemdLauncherSocket, agentaccount.Linux, stopBudgetSeconds),

		SystemdLauncherSocket: fmt.Appendf(nil, `# %[1]s

[Unit]
Description=Localport session launcher socket
Documentation=https://localport.io/docs

[Socket]
ListenStream=%[2]s
SocketUser=root
SocketGroup=%[3]s
SocketMode=0660
# The directory systemd creates is root:root; the socket's mode and group
# are the access control.
DirectoryMode=0755

[Install]
WantedBy=sockets.target
`, Marker, launcher.LinuxSocketPath, agentaccount.Linux),

		SystemdLauncherService: fmt.Appendf(nil, `# %[1]s

[Unit]
Description=Localport session launcher
Documentation=https://localport.io/docs
Requires=%[3]s
After=%[3]s

[Service]
ExecStart=%[2]s launcher
Restart=on-failure
# Sessions are children of the launcher; a stop or restart leaves them
# running, each with its own channel to the agent.
KillMode=process
# No sandboxing: every session inherits the launcher's, and a session must
# reach the network, devices and setuid programs as a login does.
`, Marker, session, SystemdLauncherSocket),
	}, nil
}

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// The OpenRC services: the agent and the session launcher, init scripts in
// /etc/init.d run by supervise-daemon.
const (
	OpenRCService         = "localport-device"
	OpenRCLauncherService = "localport-session"
	openrcInitDir         = "/etc/init.d"
	openrcRunlevelDir     = "/etc/runlevels"
)

// openrcNotRunning are the exit statuses of `rc-service <name> status` for a
// service that is not started: stopped 3, stopping 4, starting 8, inactive
// 16, crashed 32 (openrc-run.sh _status). Exit 1 is rc-service's own failure.
var openrcNotRunning = []int{3, 4, 8, 16, 32}

// The OpenRC logs: supervise-daemon opens an output_log once, so each
// process opens and rotates its own (--log-file), as under launchd.
const (
	openrcAgentLogDir = AgentLogDir
	openrcAgentLog    = openrcAgentLogDir + "/device.log"
	openrcLauncherLog = "/var/log/localport-session.log"
)

// openrc manages the device service and the session launcher as OpenRC
// services in the default runlevel.
type openrc struct {
	initDir string
	// runlevelDir holds a directory per runlevel with a link per service in
	// it (/etc/runlevels).
	runlevelDir string
	// rcService and rcUpdate are the absolute paths of rc-service and
	// rc-update.
	rcService, rcUpdate string
	logDir              string
	account             func() (Account, error)
	run                 runner
}

func (o openrc) Name() string { return OpenRCService }

func (o openrc) script(name string) string { return filepath.Join(o.initDir, name) }

func (o openrc) paths() []string {
	return []string{o.script(OpenRCLauncherService), o.script(OpenRCService)}
}

// Check refuses an init script without Marker. OpenRC loads a service only
// from its script in /etc/init.d, so the file is the whole definition.
func (o openrc) Check() ([]string, error) { return nil, checkOwned(o.paths()...) }

func (o openrc) Installed() (bool, error) { return owned(o.script(OpenRCService)) }

// MainPID asks the agent's script for the child pid supervise-daemon
// records. A status that reports the service not started (openrcNotRunning)
// gives 0; any other failure is an error.
func (o openrc) MainPID(ctx context.Context) (int, error) {
	if _, err := o.run(ctx, o.rcService, OpenRCService, "status"); err != nil {
		var cmdErr *CommandError
		if errors.As(err, &cmdErr) && slices.Contains(openrcNotRunning, cmdErr.ExitCode) {
			return 0, nil
		}
		return 0, err
	}
	out, err := o.run(ctx, o.rcService, OpenRCService, "mainpid")
	if err != nil {
		return 0, err
	}
	value := strings.TrimSpace(out)
	if value == "" {
		return 0, nil
	}
	pid, err := strconv.Atoi(value)
	if err != nil {
		return 0, errManager.With(err, fmt.Sprintf("%s %s mainpid: %q", o.rcService, OpenRCService, value))
	}
	return pid, nil
}

// Install writes both scripts, adds them to the default runlevel and starts
// the launcher and (re)starts the agent. A running launcher is restarted so
// an upgraded binary takes effect; supervise-daemon signals only its child,
// so open sessions keep running.
func (o openrc) Install(ctx context.Context, exe string) error {
	if err := checkOwned(o.paths()...); err != nil {
		return err
	}
	scripts, err := openrcScripts(exe)
	if err != nil {
		return err
	}
	acct, err := o.account()
	if err != nil {
		return err
	}
	if err := prepareLogDir(o.logDir, acct); err != nil {
		return err
	}
	for _, name := range []string{OpenRCLauncherService, OpenRCService} {
		if err := writeOwnedMode(o.script(name), scripts[name], 0o755); err != nil {
			return err
		}
	}
	for _, args := range [][]string{
		{o.rcUpdate, "add", OpenRCLauncherService, "default"},
		{o.rcUpdate, "add", OpenRCService, "default"},
		// restart starts a stopped service and restarts a running one.
		{o.rcService, OpenRCLauncherService, "restart"},
		{o.rcService, OpenRCService, "restart"},
	} {
		if _, err := o.run(ctx, args[0], args[1:]...); err != nil {
			return err
		}
	}
	return nil
}

func (o openrc) Restart(ctx context.Context) error {
	_, err := o.run(ctx, o.rcService, OpenRCService, "restart")
	return err
}

// Reload runs the script's reload, which sends SIGHUP to the agent.
func (o openrc) Reload(ctx context.Context) error {
	_, err := o.run(ctx, o.rcService, OpenRCService, "reload")
	return err
}

// Uninstall stops both services, removes them from every runlevel and
// deletes their scripts.
func (o openrc) Uninstall(ctx context.Context) error {
	if err := checkOwned(o.paths()...); err != nil {
		return err
	}
	exists, err := owned(o.script(OpenRCService))
	if err != nil {
		return err
	}
	if !exists {
		return ErrNotInstalled
	}
	for _, name := range []string{OpenRCService, OpenRCLauncherService} {
		if _, err := o.run(ctx, o.rcService, name, "stop"); err != nil {
			return err
		}
		runlevels, err := o.runlevelsOf(name)
		if err != nil {
			return err
		}
		for _, runlevel := range runlevels {
			if _, err := o.run(ctx, o.rcUpdate, "del", name, runlevel); err != nil {
				return err
			}
		}
		if err := removeOwned(o.script(name)); err != nil && !errors.Is(err, ErrNotInstalled) {
			return err
		}
	}
	return nil
}

// runlevelsOf lists the runlevels that link name. rc-update del exits 1
// alike for "not in that runlevel" and for a real failure, so Uninstall
// deletes only where a link exists and treats every failure as an error.
func (o openrc) runlevelsOf(name string) ([]string, error) {
	levels, err := os.ReadDir(o.runlevelDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errManager.With(err, "read "+o.runlevelDir)
	}
	var in []string
	for _, level := range levels {
		switch _, err := os.Lstat(filepath.Join(o.runlevelDir, level.Name(), name)); {
		case err == nil:
			in = append(in, level.Name())
		case !errors.Is(err, os.ErrNotExist):
			return nil, errManager.With(err, "inspect runlevel "+level.Name())
		}
	}
	return in, nil
}

// openrcScripts are the init scripts for the agent at exe and the launcher
// beside it, by service name. The paths are written into the scripts as shell
// strings without escaping, so they must match systemdSafePath.
func openrcScripts(exe string) (map[string][]byte, error) {
	if !systemdSafePath.MatchString(exe) {
		return nil, ErrUnsafeExecutable.With(nil, fmt.Sprintf("%q (OpenRC needs an absolute path of letters, digits and ._+@/-)", exe))
	}
	return map[string][]byte{
		OpenRCService: fmt.Appendf(nil, `#!/sbin/openrc-run
# %[1]s
# Configure the devices with localport set; /etc/localport-device/agent.yaml
# holds their settings and /etc/localport-device/identity their private keys,
# so keep that directory out of backups and configuration management.

description="Localport fleet device agent"
supervisor=supervise-daemon
command="%[2]s"
command_args="run --service --log-file %[3]s"
command_user="%[4]s:%[4]s"
umask=077
no_new_privs=yes
# A core dump would contain the device's private keys.
rc_ulimit="-c 0"
respawn_delay=5
respawn_max=0
# SIGTERM, then SIGKILL once the agent had its stop budget to end sessions.
retry="TERM/%[6]d/KILL/5"
extra_started_commands="reload mainpid"

depend() {
	need net %[5]s
	after %[5]s
}

# localport set changes the config and reloads; the agent applies the
# changed devices only.
reload() {
	ebegin "Reloading ${RC_SVCNAME}"
	supervise-daemon "${RC_SVCNAME}" --signal HUP
	eend $?
}

mainpid() {
	service_get_value child_pid
}
`, Marker, exe, openrcAgentLog, AgentAccount, OpenRCLauncherService, stopBudgetSeconds),

		OpenRCLauncherService: fmt.Appendf(nil, `#!/sbin/openrc-run
# %[1]s

description="Localport session launcher"
supervisor=supervise-daemon
command="%[2]s"
command_args="launcher --log-file %[3]s"
respawn_delay=1
respawn_max=0
# Sessions are children of the launcher. supervise-daemon stops only its
# child, so a stop or restart leaves them running, each with its own channel
# to the agent. The launcher binds its socket itself.
`, Marker, SessionExecutable(exe), openrcLauncherLog),
	}, nil
}

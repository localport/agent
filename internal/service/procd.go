package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
)

// The OpenWrt procd services: init scripts in /etc/init.d through
// /etc/rc.common with USE_PROCD. Their output goes to logd (stdout and stderr),
// so no process opens a log file.
const (
	ProcdService         = "localport-device"
	ProcdLauncherService = "localport-session"
	procdInitDir         = "/etc/init.d"
)

// procd manages the device service and the session launcher as procd
// services.
type procd struct {
	initDir string
	// ubus is the absolute path of ubus.
	ubus string
	run  runner
}

func (p procd) Name() string { return ProcdService }

func (p procd) script(name string) string { return filepath.Join(p.initDir, name) }

func (p procd) paths() []string {
	return []string{p.script(ProcdLauncherService), p.script(ProcdService)}
}

// Check refuses an init script without Marker.
func (p procd) Check() ([]string, error) { return nil, checkOwned(p.paths()...) }

func (p procd) Installed() (bool, error) { return owned(p.script(ProcdService)) }

// procdList is the part of `ubus call service list` this package reads.
type procdList map[string]struct {
	Instances map[string]struct {
		Running bool `json:"running"`
		PID     int  `json:"pid"`
	} `json:"instances"`
}

// MainPID is the pid of the agent's instance while procd reports it
// running, and 0 otherwise.
func (p procd) MainPID(ctx context.Context) (int, error) {
	out, err := p.run(ctx, p.ubus, "call", "service", "list", `{"name":"`+ProcdService+`"}`)
	if err != nil {
		return 0, err
	}
	var list procdList
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return 0, errManager.With(err, "ubus call service list")
	}
	for _, in := range list[ProcdService].Instances {
		if in.Running {
			return in.PID, nil
		}
	}
	return 0, nil
}

// Install writes both scripts, enables them and starts them. procd restarts a
// running instance when a start brings a changed definition; the launcher's
// definition names its binary as a file, so an upgrade changes its checksum
// and restarts it, and a reinstall of the same binary leaves it running.
// procd kills an instance's cgroup whenever the instance exits, so a launcher
// restart or stop ends the sessions it started.
func (p procd) Install(ctx context.Context, exe string) error {
	if err := checkOwned(p.paths()...); err != nil {
		return err
	}
	scripts, err := procdScripts(exe)
	if err != nil {
		return err
	}
	for _, name := range []string{ProcdLauncherService, ProcdService} {
		if err := writeOwnedMode(p.script(name), scripts[name], 0o755); err != nil {
			return err
		}
	}
	for _, args := range [][]string{
		{p.script(ProcdLauncherService), "enable"},
		{p.script(ProcdLauncherService), "start"},
		{p.script(ProcdService), "enable"},
		// restart starts a stopped agent and restarts a running one, so a
		// reinstall or an upgrade runs the new script and binary.
		{p.script(ProcdService), "restart"},
	} {
		if _, err := p.run(ctx, args[0], args[1:]...); err != nil {
			return err
		}
	}
	return nil
}

func (p procd) Restart(ctx context.Context) error {
	_, err := p.run(ctx, p.script(ProcdService), "restart")
	return err
}

// Reload runs the script's reload_service, which sends SIGHUP to the agent.
func (p procd) Reload(ctx context.Context) error {
	_, err := p.run(ctx, p.script(ProcdService), "reload")
	return err
}

// Uninstall stops and disables both services and deletes their scripts.
func (p procd) Uninstall(ctx context.Context) error {
	if err := checkOwned(p.paths()...); err != nil {
		return err
	}
	exists, err := owned(p.script(ProcdService))
	if err != nil {
		return err
	}
	if !exists {
		return ErrNotInstalled
	}
	for _, name := range []string{ProcdService, ProcdLauncherService} {
		script := p.script(name)
		if exists, _ := owned(script); exists {
			for _, action := range []string{"stop", "disable"} {
				if _, err := p.run(ctx, script, action); err != nil {
					return err
				}
			}
		}
		if err := removeOwned(script); err != nil && !errors.Is(err, ErrNotInstalled) {
			return err
		}
	}
	return nil
}

// procdScripts are the init scripts for the agent at exe and the launcher
// beside it, by service name. START orders the launcher before the agent.
func procdScripts(exe string) (map[string][]byte, error) {
	if !systemdSafePath.MatchString(exe) {
		return nil, ErrUnsafeExecutable.With(nil, fmt.Sprintf("%q (procd needs an absolute path of letters, digits and ._+@/-)", exe))
	}
	return map[string][]byte{
		ProcdService: fmt.Appendf(nil, `#!/bin/sh /etc/rc.common
# %[1]s
# Configure the devices with localport set; /etc/localport-device/agent.yaml
# holds their settings and /etc/localport-device/identity their private keys.

USE_PROCD=1
START=96
STOP=10

start_service() {
	procd_open_instance
	procd_set_param command %[2]s run --service
	procd_set_param user %[3]s
	procd_set_param group %[3]s
	procd_set_param no_new_privs 1
	# A core dump would contain the device's private keys.
	procd_set_param limits core="0 0"
	procd_set_param respawn 3600 5 0
	procd_set_param term_timeout %[5]d
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_close_instance
}

# localport set changes the config and reloads; the agent applies the
# changed devices only.
reload_service() {
	procd_send_signal %[4]s '*' HUP
}
`, Marker, exe, AgentAccount, ProcdService, stopBudgetSeconds),

		ProcdLauncherService: fmt.Appendf(nil, `#!/bin/sh /etc/rc.common
# %[1]s
# The launcher binds its socket itself. Sessions are its children, in its
# instance cgroup.

USE_PROCD=1
START=95
STOP=11

start_service() {
	procd_open_instance
	procd_set_param command %[2]s launcher
	procd_set_param file %[2]s
	procd_set_param respawn 3600 1 0
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_close_instance
}
`, Marker, SessionExecutable(exe)),
	}, nil
}

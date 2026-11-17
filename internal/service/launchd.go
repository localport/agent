package service

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/localport/agent/internal/agentaccount"
	"github.com/localport/agent/internal/launcher"
)

// LaunchdLabel is the device service's launchd label.
const LaunchdLabel = "io.localport.device"

// LaunchdLauncherLabel is the session launcher's launchd label.
const LaunchdLauncherLabel = "io.localport.session"

// LaunchdPlistPath is where the daemon's plist is installed; the launcher's
// sits beside it.
const LaunchdPlistPath = "/Library/LaunchDaemons/" + LaunchdLabel + ".plist"

// The service logs. Each process opens and rotates its own (internal/logfile),
// since launchd opens a StandardOutPath once and never reopens it. The agent's
// log is in a directory of its own account, since rotating renames files in the
// directory; the root launcher's is in /var/log.
const (
	launchdAgentLogDir = AgentLogDir
	launchdAgentLog    = launchdAgentLogDir + "/device.log"
	launchdLauncherLog = "/var/log/localport-session.log"
)

// launchdSocketName is the Sockets key the launcher checks in with
// (launch_activate_socket); cmd/localport-session names the same.
const launchdSocketName = "Listeners"

const launchctlPath = "/bin/launchctl"

// bootoutWait bounds the wait for launchd to finish a bootout, polled every
// bootoutPoll: launchctl offers no completion event, and a bootstrap that
// races the bootout fails. It outlasts the agent's ExitTimeOut (StopBudget).
const (
	bootoutWait = StopBudget + 5*time.Second
	bootoutPoll = 200 * time.Millisecond
)

// launchd manages the device service and the session launcher as launchd
// daemons in the system domain: the agent as AgentAccount, the launcher as
// root. plistPath is the agent's; the launcher's sits beside it.
type launchd struct {
	plistPath string
	// logDir is launchdAgentLogDir outside tests.
	logDir string
	// account resolves the agent account's ids (LookupAccount).
	account func() (Account, error)
	run     runner
}

// job is one daemon this manager installs.
type job struct {
	label, plist string
}

func (l launchd) Name() string { return LaunchdLabel }

func (l launchd) jobs() []job {
	dir := filepath.Dir(l.plistPath)
	return []job{
		{LaunchdLauncherLabel, filepath.Join(dir, LaunchdLauncherLabel+".plist")},
		{LaunchdLabel, l.plistPath},
	}
}

func (l launchd) plists() []string {
	var paths []string
	for _, j := range l.jobs() {
		paths = append(paths, j.plist)
	}
	return paths
}

func target(label string) string { return "system/" + label }

// Check refuses a plist without Marker, and a loaded job whose plist is not
// ours.
func (l launchd) Check() ([]string, error) {
	if err := checkOwned(l.plists()...); err != nil {
		return nil, err
	}
	for _, j := range l.jobs() {
		if exists, _ := owned(j.plist); exists {
			continue
		}
		loaded, err := l.loaded(context.Background(), j.label)
		if err != nil {
			return nil, err
		}
		if loaded {
			return nil, ErrForeignUnit.With(nil, fmt.Sprintf("launchd has %s loaded, but not from %s; unload it with launchctl bootout %s, then run the command again", j.label, j.plist, target(j.label)))
		}
	}
	return nil, nil
}

func (l launchd) Installed() (bool, error) { return owned(l.plistPath) }

// Install writes both plists and boots each daemon out and in again, the
// launcher first, so the agent's first session finds its socket.
func (l launchd) Install(ctx context.Context, exe string) error {
	if err := checkOwned(l.plists()...); err != nil {
		return err
	}
	acct, err := l.account()
	if err != nil {
		return err
	}
	plists := map[string][]byte{}
	if plists[LaunchdLabel], err = launchdAgentPlist(exe); err != nil {
		return err
	}
	if plists[LaunchdLauncherLabel], err = launchdLauncherPlist(SessionExecutable(exe), acct.GID); err != nil {
		return err
	}
	if err := prepareLogDir(l.logDir, acct); err != nil {
		return err
	}
	for _, j := range l.jobs() {
		if err := writeOwned(j.plist, plists[j.label]); err != nil {
			return err
		}
	}
	for _, j := range l.jobs() {
		// A loaded daemon keeps its old definition until it is booted out
		// and bootstrapped again.
		if err := l.bootoutIfLoaded(ctx, j.label); err != nil {
			return err
		}
		// enable clears a disabled override, which would make bootstrap fail.
		if _, err := l.run(ctx, launchctlPath, "enable", target(j.label)); err != nil {
			return err
		}
		if _, err := l.run(ctx, launchctlPath, "bootstrap", "system", j.plist); err != nil {
			return err
		}
	}
	return nil
}

func (l launchd) Restart(ctx context.Context) error {
	_, err := l.run(ctx, launchctlPath, "kickstart", "-k", target(LaunchdLabel))
	return err
}

// Reload sends SIGHUP: the agent re-reads its config.
func (l launchd) Reload(ctx context.Context) error {
	_, err := l.run(ctx, launchctlPath, "kill", "HUP", target(LaunchdLabel))
	return err
}

// Uninstall boots both daemons out and removes their plists.
func (l launchd) Uninstall(ctx context.Context) error {
	if err := checkOwned(l.plists()...); err != nil {
		return err
	}
	exists, err := owned(l.plistPath)
	if err != nil {
		return err
	}
	if !exists {
		return ErrNotInstalled
	}
	for _, j := range l.jobs() {
		if err := l.bootoutIfLoaded(ctx, j.label); err != nil {
			return err
		}
		if err := removeOwned(j.plist); err != nil && !errors.Is(err, ErrNotInstalled) {
			return err
		}
	}
	return nil
}

// MainPID reads the `state =` and `pid =` lines of launchctl print. A label
// launchd does not know, or one in any state but running, reports 0.
func (l launchd) MainPID(ctx context.Context) (int, error) {
	out, err := l.run(ctx, launchctlPath, "print", target(LaunchdLabel))
	switch {
	case launchdNotFound(err):
		return 0, nil
	case err != nil:
		return 0, err
	}
	pid, state := 0, ""
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), " = ")
		if !ok {
			continue
		}
		switch {
		case key == "state" && state == "":
			state = value
		case key == "pid" && pid == 0:
			if pid, err = strconv.Atoi(value); err != nil {
				return 0, errManager.With(err, fmt.Sprintf("launchctl print %s: pid %q", target(LaunchdLabel), value))
			}
		}
	}
	if state != "running" {
		return 0, nil
	}
	return pid, nil
}

// loaded reports whether launchd knows label; print exits
// launchctlNotFound for one it does not, and any other failure is an error.
func (l launchd) loaded(ctx context.Context, label string) (bool, error) {
	_, err := l.run(ctx, launchctlPath, "print", target(label))
	switch {
	case err == nil:
		return true, nil
	case launchdNotFound(err):
		return false, nil
	default:
		return false, err
	}
}

// launchctlNotFound is launchctl print's exit status for a label launchd
// does not know (113, in the gui/ and system/ domains).
const launchctlNotFound = 113

func launchdNotFound(err error) bool {
	var cmdErr *CommandError
	return errors.As(err, &cmdErr) && cmdErr.ExitCode == launchctlNotFound
}

// bootoutIfLoaded boots label out when launchd has it loaded and waits, at
// most bootoutWait, until launchd no longer knows it.
func (l launchd) bootoutIfLoaded(ctx context.Context, label string) error {
	loaded, err := l.loaded(ctx, label)
	if err != nil || !loaded {
		return err
	}
	if _, err := l.run(ctx, launchctlPath, "bootout", target(label)); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, bootoutWait)
	defer cancel()
	for {
		loaded, err := l.loaded(ctx, label)
		if err != nil {
			return errManager.With(err, "wait for launchd to unload "+label)
		}
		if !loaded {
			return nil
		}
		select {
		case <-ctx.Done():
			return errManager.With(ctx.Err(), "wait for launchd to unload "+label)
		case <-time.After(bootoutPoll):
		}
	}
}

// prepareLogDir creates the agent's log directory, or takes over an existing
// one, as a directory (never a symlink) of acct with mode 0750. Its parent,
// /var/log, is writable by root only, so nothing swaps it between the check
// and the chown.
func prepareLogDir(dir string, acct Account) error {
	if err := os.Mkdir(dir, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
		return errDefinition.With(err, "prepare "+dir)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return errDefinition.With(err, "prepare "+dir)
	}
	if !fi.IsDir() {
		return errDefinition.With(nil, dir+" is not a directory")
	}
	if err := os.Lchown(dir, acct.UID, acct.GID); err != nil {
		return errDefinition.With(err, "prepare "+dir)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		return errDefinition.With(err, "prepare "+dir)
	}
	return nil
}

// xmlPath escapes p for a plist <string>, refusing a relative path or a
// control character.
func xmlPath(p string) (string, error) {
	if !filepath.IsAbs(p) || strings.ContainsFunc(p, unicode.IsControl) {
		return "", ErrUnsafeExecutable.With(nil, fmt.Sprintf("%q", p))
	}
	var b bytes.Buffer
	if err := xml.EscapeText(&b, []byte(p)); err != nil {
		return "", err
	}
	return b.String(), nil
}

const plistHeader = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
`

// launchdAgentPlist is the agent's daemon definition: exe as the macOS agent
// account and group, its own rotated log.
func launchdAgentPlist(exe string) ([]byte, error) {
	program, err := xmlPath(exe)
	if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, plistHeader+`<!-- %s
     Configure the devices with localport set. /Library/Application Support/localport-device
     holds their settings and, under identity/, their private keys. -->
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>run</string>
    <string>--service</string>
    <string>--log-file</string>
    <string>%s</string>
  </array>
  <key>UserName</key>
  <string>%s</string>
  <key>GroupName</key>
  <string>%s</string>
  <key>Umask</key>
  <integer>63</integer>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ExitTimeOut</key>
  <integer>%d</integer>
  <!-- A core dump would contain the device's private keys. -->
  <key>SoftResourceLimits</key>
  <dict>
    <key>Core</key>
    <integer>0</integer>
  </dict>
  <key>HardResourceLimits</key>
  <dict>
    <key>Core</key>
    <integer>0</integer>
  </dict>
</dict>
</plist>
`, Marker, LaunchdLabel, program, launchdAgentLog, agentaccount.MacOS, agentaccount.MacOS, stopBudgetSeconds), nil
}

// launchdLauncherPlist is the launcher's daemon definition: root, with the
// socket launchd binds root:gid 0660 (SockPathMode is decimal).
func launchdLauncherPlist(session string, gid int) ([]byte, error) {
	program, err := xmlPath(session)
	if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, plistHeader+`<!-- %s -->
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>launcher</string>
    <string>--log-file</string>
    <string>%s</string>
  </array>
  <key>Sockets</key>
  <dict>
    <key>%s</key>
    <dict>
      <key>SockPathName</key>
      <string>%s</string>
      <key>SockPathOwner</key>
      <integer>0</integer>
      <key>SockPathGroup</key>
      <integer>%d</integer>
      <key>SockPathMode</key>
      <integer>432</integer>
    </dict>
  </dict>
  <!-- Sessions are the launcher's children; they keep running when it stops. -->
  <key>AbandonProcessGroup</key>
  <true/>
</dict>
</plist>
`, Marker, LaunchdLauncherLabel, program, launchdLauncherLog, launchdSocketName, launcher.DarwinSocketPath, gid), nil
}

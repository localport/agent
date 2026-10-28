package service

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// LaunchdLabel is the device service's launchd label.
const LaunchdLabel = "io.localport.device"

// LaunchdPlistPath is where the daemon's plist is installed.
const LaunchdPlistPath = "/Library/LaunchDaemons/" + LaunchdLabel + ".plist"

// launchdLog is where the daemon's output goes. launchd opens it once at
// spawn, so it is not rotated. Install creates it owner-only first, since
// launchd would create it readable by every account.
const launchdLog = "/var/log/localport-device.log"

const launchctlPath = "/bin/launchctl"

// bootoutWait bounds the wait for launchd to finish a bootout, polled every
// bootoutPoll: launchctl offers no completion event, and a bootstrap that
// races the bootout fails.
const (
	bootoutWait = 30 * time.Second
	bootoutPoll = 200 * time.Millisecond
)

// launchd manages the device service as a launchd daemon in the system
// domain, run as root. logPath is launchdLog and logUID root outside tests.
type launchd struct {
	plistPath string
	logPath   string
	logUID    int
	run       runner
}

const launchdTarget = "system/" + LaunchdLabel

func (l launchd) Name() string { return LaunchdLabel }

// Check refuses a plist without Marker, and a loaded io.localport.device
// whose plist is not ours.
func (l launchd) Check() ([]string, error) {
	exists, err := owned(l.plistPath)
	if err != nil || exists {
		return nil, err
	}
	loaded, err := l.loaded(context.Background())
	if err != nil {
		return nil, err
	}
	if loaded {
		return nil, fmt.Errorf("%w: launchd has %s loaded, but not from %s; unload it with launchctl bootout %s, then run the command again", ErrForeignUnit, LaunchdLabel, l.plistPath, launchdTarget)
	}
	return nil, nil
}

func (l launchd) Installed() (bool, error) { return owned(l.plistPath) }

func (l launchd) Install(ctx context.Context, exe string) error {
	plist, err := launchdPlist(exe)
	if err != nil {
		return err
	}
	if err := writeOwned(l.plistPath, plist); err != nil {
		return err
	}
	if err := prepareLog(l.logPath, l.logUID); err != nil {
		return err
	}
	// A loaded daemon keeps its old definition and credential until it is
	// booted out and bootstrapped again.
	if err := l.bootoutIfLoaded(ctx); err != nil {
		return err
	}
	// enable clears a disabled override, which would make bootstrap fail.
	if _, err := l.run(ctx, launchctlPath, "enable", launchdTarget); err != nil {
		return err
	}
	_, err = l.run(ctx, launchctlPath, "bootstrap", "system", l.plistPath)
	return err
}

func (l launchd) Restart(ctx context.Context) error {
	_, err := l.run(ctx, launchctlPath, "kickstart", "-k", launchdTarget)
	return err
}

// Uninstall boots the daemon out and removes its plist.
func (l launchd) Uninstall(ctx context.Context) error {
	exists, err := owned(l.plistPath)
	if err != nil {
		return err
	}
	if !exists {
		return ErrNotInstalled
	}
	if err := l.bootoutIfLoaded(ctx); err != nil {
		return err
	}
	return removeOwned(l.plistPath)
}

// MainPID reads the `state =` and `pid =` lines of launchctl print. A label
// launchd does not know, or one in any state but running, reports 0.
func (l launchd) MainPID(ctx context.Context) (int, error) {
	out, err := l.run(ctx, launchctlPath, "print", launchdTarget)
	var cmdErr *CommandError
	switch {
	case errors.As(err, &cmdErr) && cmdErr.ExitCode > 0:
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
				return 0, fmt.Errorf("launchctl print %s: pid %q: %w", launchdTarget, value, err)
			}
		}
	}
	if state != "running" {
		return 0, nil
	}
	return pid, nil
}

// loaded reports whether launchd knows the label; print exits non-zero for
// one it does not.
func (l launchd) loaded(ctx context.Context) (bool, error) {
	_, err := l.run(ctx, launchctlPath, "print", launchdTarget)
	var cmdErr *CommandError
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &cmdErr) && cmdErr.ExitCode > 0:
		return false, nil
	default:
		return false, err
	}
}

// bootoutIfLoaded boots the daemon out when launchd has it loaded and waits,
// at most bootoutWait, until launchd no longer knows the label.
func (l launchd) bootoutIfLoaded(ctx context.Context) error {
	loaded, err := l.loaded(ctx)
	if err != nil || !loaded {
		return err
	}
	if _, err := l.run(ctx, launchctlPath, "bootout", launchdTarget); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, bootoutWait)
	defer cancel()
	for {
		loaded, err := l.loaded(ctx)
		if err != nil {
			return fmt.Errorf("wait for launchd to unload %s: %w", LaunchdLabel, err)
		}
		if !loaded {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for launchd to unload %s: %w", LaunchdLabel, ctx.Err())
		case <-time.After(bootoutPoll):
		}
	}
}

// prepareLog creates the daemon's log file, or takes over an existing one,
// as a regular file of uid with mode 0600. The log directory is writable by
// root only, so the file cannot be swapped between the check and the open.
func prepareLog(path string, uid int) error {
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("prepare %s: not a regular file", path)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("prepare %s: %w", path, err)
	}
	defer f.Close()
	if err := f.Chown(uid, -1); err != nil {
		return fmt.Errorf("prepare %s: %w", path, err)
	}
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("prepare %s: %w", path, err)
	}
	return nil
}

// launchdPlist is the daemon definition running exe.
func launchdPlist(exe string) ([]byte, error) {
	if !filepath.IsAbs(exe) || strings.ContainsFunc(exe, unicode.IsControl) {
		return nil, fmt.Errorf("%w: %q", ErrUnsafeExecutable, exe)
	}
	var program bytes.Buffer
	if err := xml.EscapeText(&program, []byte(exe)); err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- %s
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
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>%s</string>
  <key>StandardErrorPath</key>
  <string>%s</string>
</dict>
</plist>
`, Marker, LaunchdLabel, program.String(), launchdLog, launchdLog), nil
}

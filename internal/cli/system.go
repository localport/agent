package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/localport/agent/internal/errcode"
)

// `localport system <step>` is the Windows installer's internal command: the
// NSIS installer and uninstaller run each step from the new localport.exe and
// check its exit status. It is hidden from `localport help`, refuses unless
// elevated, and is built on Windows only (system_windows.go); the step logic
// here is platform-neutral so it is tested on every platform.

var (
	errInstallerNotElevated = errcode.New(errcode.InstallerNotElevated)
	errInstallDirUnsafe     = errcode.New(errcode.InstallDirUnsafe)
	errServicesNotStopped   = errcode.New(errcode.ServicesNotStopped)
	errInstallNotCommitted  = errcode.New(errcode.InstallNotCommitted)
	errServicesNotRestored  = errcode.New(errcode.ServicesNotRestored)
	errForeignServiceInDir  = errcode.New(errcode.ForeignServiceInDir)
	errMachinePathNotSet    = errcode.New(errcode.MachinePathNotSet)
)

// installBinaries are the executables the installer ships, committed together
// so localport.exe and localport-session.exe always come from one release.
var installBinaries = []string{"localport.exe", "localport-session.exe"}

// stagingPrefix names the directory inside the install directory the
// installer extracts the new executables into.
const stagingPrefix = ".staging-"

// installHost is what the steps need from the machine: elevation, the install
// directory's permissions, the device services and the machine Path.
type installHost interface {
	elevated() bool
	// prepareInstallDir creates dir admin-only when it is missing, then
	// refuses it unless it passes the device service binary rule.
	prepareInstallDir(dir string) error
	// stopServices stops the owned device and launcher services and waits
	// until each is stopped; it returns the names it stopped.
	stopServices(ctx context.Context) ([]string, error)
	startServices(ctx context.Context, names []string) error
	// servicesInstalled reports whether an owned device service exists.
	servicesInstalled() (bool, error)
	// reregister runs `service install` from dir's localport.exe.
	reregister(ctx context.Context, dir string) error
	// foreignServicesIn lists services not created by localport whose
	// program is inside dir.
	foreignServicesIn(dir string) ([]string, error)
	uninstallServices(purge bool) error
	readPath() (value string, expandable bool, err error)
	writePath(value string, expandable bool) error
	broadcastEnvironment() error
	expand(s string) string
}

// runSystemSteps runs one installer step on host.
func runSystemSteps(ctx context.Context, host installHost, args []string) error {
	if len(args) == 0 {
		return errors.New("system: name a step: preflight, stop, commit, reregister, preuninstall or path")
	}
	if !host.elevated() {
		return fmt.Errorf("%w: system %s", errInstallerNotElevated, args[0])
	}
	step, rest := args[0], args[1:]
	dirArg := func(n int) (string, error) {
		if len(rest) != n || !filepath.IsAbs(rest[0]) {
			return "", fmt.Errorf("system %s: want %d argument(s), the first an absolute directory", step, n)
		}
		return filepath.Clean(rest[0]), nil
	}
	switch step {
	case "preflight":
		dir, err := dirArg(1)
		if err != nil {
			return err
		}
		if err := host.prepareInstallDir(dir); err != nil {
			return fmt.Errorf("%w: %s: %w", errInstallDirUnsafe, dir, err)
		}
		return nil
	case "stop":
		if _, err := dirArg(1); err != nil {
			return err
		}
		stopped, err := host.stopServices(ctx)
		if err != nil {
			return errors.Join(fmt.Errorf("%w: %w", errServicesNotStopped, err), host.startServices(ctx, stopped))
		}
		return nil
	case "commit":
		dir, err := dirArg(2)
		if err != nil {
			return err
		}
		if err := commitBinaries(dir, rest[1], installBinaries); err != nil {
			// The previous executables are back; the services stop asked for
			// run them again.
			return errors.Join(fmt.Errorf("%w: %w", errInstallNotCommitted, err), restartOwned(ctx, host))
		}
		return nil
	case "reregister":
		dir, err := dirArg(1)
		if err != nil {
			return err
		}
		installed, err := host.servicesInstalled()
		if err != nil {
			return fmt.Errorf("%w: %w", errServicesNotRestored, err)
		}
		if !installed {
			return nil
		}
		if err := host.reregister(ctx, dir); err != nil {
			return fmt.Errorf("%w: %w", errServicesNotRestored, err)
		}
		return nil
	case "preuninstall":
		purge := len(rest) == 2 && rest[1] == "--purge"
		if purge {
			rest = rest[:1]
		}
		dir, err := dirArg(1)
		if err != nil {
			return err
		}
		foreign, err := host.foreignServicesIn(dir)
		if err != nil {
			return err
		}
		if len(foreign) > 0 {
			return fmt.Errorf("%w: %s", errForeignServiceInDir, strings.Join(foreign, ", "))
		}
		return host.uninstallServices(purge)
	case "path":
		if len(rest) != 2 || (rest[0] != "add" && rest[0] != "remove") || !filepath.IsAbs(rest[1]) {
			return errors.New("system path: want add or remove and an absolute directory")
		}
		if err := editMachinePath(host, rest[0], filepath.Clean(rest[1])); err != nil {
			return fmt.Errorf("%w: %w", errMachinePathNotSet, err)
		}
		return nil
	}
	return fmt.Errorf("system: unknown step %q", step)
}

// restartOwned starts the owned services again after a refused commit.
func restartOwned(ctx context.Context, host installHost) error {
	installed, err := host.servicesInstalled()
	if err != nil || !installed {
		return err
	}
	return host.startServices(ctx, nil)
}

// commitBinaries moves each of names from dir\staging into dir: the current
// file is renamed to <name>.old (Windows renames a running image), then the
// staged file takes its place. Any failure moves every file back, so the
// directory never holds executables from two releases. On success it removes
// the .old files and every staging directory, this one and leftovers of
// earlier runs.
func commitBinaries(dir, staging string, names []string) error {
	if staging != filepath.Base(staging) || !strings.HasPrefix(staging, stagingPrefix) {
		return fmt.Errorf("staging directory %q is not a %s* name inside %s", staging, stagingPrefix, dir)
	}
	stagingDir := filepath.Join(dir, staging)
	for _, name := range names {
		if fi, err := os.Lstat(filepath.Join(stagingDir, name)); err != nil || !fi.Mode().IsRegular() {
			return fmt.Errorf("staged %s is missing or not a regular file: %v", name, err)
		}
	}
	type move struct{ from, to string }
	var done []move
	rollback := func(cause error) error {
		var errs []error
		for i := len(done) - 1; i >= 0; i-- {
			errs = append(errs, os.Rename(done[i].to, done[i].from))
		}
		if err := errors.Join(errs...); err != nil {
			return fmt.Errorf("%w; restoring the previous files also failed: %w", cause, err)
		}
		return cause
	}
	for _, name := range names {
		current, old := filepath.Join(dir, name), filepath.Join(dir, name+".old")
		if err := removeIfPresent(old); err != nil {
			return rollback(err)
		}
		switch err := os.Rename(current, old); {
		case err == nil:
			done = append(done, move{current, old})
		case !errors.Is(err, fs.ErrNotExist):
			return rollback(fmt.Errorf("set aside %s: %w", current, err))
		}
		if err := os.Rename(filepath.Join(stagingDir, name), current); err != nil {
			return rollback(fmt.Errorf("put %s in place: %w", current, err))
		}
		done = append(done, move{filepath.Join(stagingDir, name), current})
	}
	return cleanInstallDir(dir, names)
}

// cleanInstallDir removes the .old files of names and every staging
// directory in dir. A file still held open (a .old image of a process that
// has not exited) stays until the next commit.
func cleanInstallDir(dir string, names []string) error {
	for _, name := range names {
		_ = removeIfPresent(filepath.Join(dir, name+".old"))
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), stagingPrefix) {
			_ = os.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
	return nil
}

func removeIfPresent(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// editMachinePath adds dir to, or removes it from, the machine Path, keeping
// the value's registry type and every other entry byte for byte, and
// broadcasts the change. An entry matches dir when equal ignoring case and a
// trailing separator, as written or after environment expansion. Adding
// refuses a directory that does not exist.
func editMachinePath(host installHost, op, dir string) error {
	if op == "add" {
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			return fmt.Errorf("%s is not an existing directory", dir)
		}
	}
	value, expandable, err := host.readPath()
	if err != nil {
		return err
	}
	next := pathWithout(value, dir, host.expand)
	if op == "add" {
		next = pathWith(value, dir, host.expand)
	}
	if next == value {
		return nil
	}
	if err := host.writePath(next, expandable); err != nil {
		return err
	}
	return host.broadcastEnvironment()
}

func pathEntryMatches(entry, dir string, expand func(string) string) bool {
	norm := func(s string) string { return strings.TrimRight(s, `\/`) }
	return strings.EqualFold(norm(entry), norm(dir)) || strings.EqualFold(norm(expand(entry)), norm(dir))
}

// pathWith is value with dir appended unless an entry already matches it.
func pathWith(value, dir string, expand func(string) string) string {
	for _, e := range strings.Split(value, ";") {
		if e != "" && pathEntryMatches(e, dir, expand) {
			return value
		}
	}
	if value == "" || strings.HasSuffix(value, ";") {
		return value + dir
	}
	return value + ";" + dir
}

// pathWithout is value without the entries that match dir.
func pathWithout(value, dir string, expand func(string) string) string {
	entries := strings.Split(value, ";")
	kept := entries[:0]
	for _, e := range entries {
		if e == "" || !pathEntryMatches(e, dir, expand) {
			kept = append(kept, e)
		}
	}
	return strings.Join(kept, ";")
}

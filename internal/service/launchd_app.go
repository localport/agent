package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/security"
)

// On macOS the session launcher runs from Localport.app, so a Full Disk Access
// grant names "Localport" and is keyed to the bundle identifier and the
// signing certificate, which every release keeps. The release ships the
// bundle beside the CLI; installing the service copies it to LaunchdAppPath.
const (
	// AppName is the bundle's directory name, beside the CLI and installed.
	AppName = "Localport.app"
	// LaunchdAppPath is the installed bundle the launcher plist runs.
	LaunchdAppPath = "/Library/Application Support/Localport/" + AppName
	// AppBundleID is the bundle's CFBundleIdentifier and code signing identifier.
	AppBundleID = "io.localport.session"
	// appExecutable is the launcher inside a bundle.
	appExecutable = "Contents/MacOS/localport-session"
	codesignPath  = "/usr/bin/codesign"
)

var sha1Hex = regexp.MustCompile(`^[0-9a-f]{40}$`)

// errAppInvalid is a session app that is missing beside the CLI, is not a
// plain bundle, or is not signed by Localport.
var errAppInvalid = errcode.New(errcode.SessionAppInvalid)

// sessionApp installs the launcher bundle. path is LaunchdAppPath outside
// tests; uid and gid own every installed file (root outside tests); verify
// checks a bundle's code signature (codesignVerify outside tests).
type sessionApp struct {
	path     string
	uid, gid int
	verify   func(ctx context.Context, bundle string) error
}

// AppChecker is a Manager whose Install also installs a session app from
// beside the CLI. CheckApp refuses, before a join token is spent, an app
// Install refuses (AG014).
type AppChecker interface {
	CheckApp(ctx context.Context, exe string) error
}

// CheckApp checks the bundle beside exe (sessionApp.check).
func (l launchd) CheckApp(ctx context.Context, exe string) error { return l.app.check(ctx, exe) }

// executable is the launcher inside the installed bundle.
func (a sessionApp) executable() string { return filepath.Join(a.path, appExecutable) }

// appRequirement is the code requirement a bundle must meet: the bundle
// identifier and, for a release build, the release certificate as leaf.
func appRequirement(certSHA1 string) (string, error) {
	req := `identifier "` + AppBundleID + `"`
	if certSHA1 == "" {
		return req, nil
	}
	if !sha1Hex.MatchString(certSHA1) {
		return "", errAppInvalid.With(nil, "this build names a malformed release certificate fingerprint")
	}
	return req + ` and certificate leaf = H"` + certSHA1 + `"`, nil
}

// install copies the bundle beside exe to a staging directory next to
// a.path, makes it owned by a.uid:a.gid and writable by the owner only,
// verifies the staged copy's signature, then exchanges it with the installed
// bundle in one rename (exchange) and removes the old one. Files are never
// overwritten in place: launchd kills a launcher whose signed file changed
// under it. Any failure leaves the installed bundle as it was. Runs under the
// install lock, so removeLeftovers never deletes a live stage.
func (a sessionApp) install(ctx context.Context, exe string) error {
	src, err := appBeside(exe)
	if err != nil {
		return err
	}
	parent := filepath.Dir(a.path)
	if err := a.ensureDir(parent); err != nil {
		return err
	}
	unlock, err := lockInstall(parent)
	if err != nil {
		return err
	}
	defer unlock()
	removeLeftovers(parent)
	staged, err := os.MkdirTemp(parent, ".staged-")
	if err != nil {
		return errDefinition.With(err, "stage "+AppName)
	}
	defer os.RemoveAll(staged)
	bundle := filepath.Join(staged, AppName)
	if err := a.copyTree(src, bundle); err != nil {
		return err
	}
	if err := a.verify(ctx, bundle); err != nil {
		return err
	}
	// An installed bundle is exchanged with the staged one in one rename, so
	// there is no moment without a bundle and no restore to fail; the old one
	// lands in the staging directory, which the deferred removal deletes.
	if _, err := os.Lstat(a.path); errors.Is(err, fs.ErrNotExist) {
		err = os.Rename(bundle, a.path)
		if err != nil {
			return errDefinition.With(err, "install "+a.path)
		}
		return nil
	} else if err != nil {
		return errDefinition.With(err, "inspect "+a.path)
	}
	if err := exchange(bundle, a.path); err != nil {
		return errDefinition.With(err, "replace "+a.path)
	}
	return nil
}

// check refuses, before anything is written or a join token is spent, a
// bundle beside exe that install refuses: missing, or not signed as
// verify requires. install verifies its own staged copy again.
func (a sessionApp) check(ctx context.Context, exe string) error {
	src, err := appBeside(exe)
	if err != nil {
		return err
	}
	return a.verify(ctx, src)
}

// appBeside is the bundle in exe's directory, refused unless it is a directory.
func appBeside(exe string) (string, error) {
	src := filepath.Join(filepath.Dir(exe), AppName)
	fi, err := os.Lstat(src)
	switch {
	case err != nil:
		return "", errAppInvalid.With(err, fmt.Sprintf("%s is missing: install localport with the install script, or extract the release's Localport app archive next to %s", src, exe))
	case !fi.IsDir():
		return "", errAppInvalid.With(nil, fmt.Sprintf("%s is not a folder: install localport with the install script, or extract the release's Localport app archive next to %s", src, exe))
	}
	return src, nil
}

func (a sessionApp) installed() bool {
	fi, err := os.Lstat(a.path)
	return err == nil && fi.IsDir()
}

// uninstall removes the installed bundle and, when empty, its directory,
// under the install lock.
func (a sessionApp) uninstall() error {
	parent := filepath.Dir(a.path)
	if _, err := os.Lstat(parent); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	unlock, err := lockInstall(parent)
	if err != nil {
		if _, statErr := os.Lstat(parent); errors.Is(statErr, fs.ErrNotExist) {
			return nil // a concurrent uninstall finished first
		}
		return err
	}
	defer unlock()
	removeLeftovers(parent)
	if err := os.RemoveAll(a.path); err != nil {
		return errDefinition.With(err, "remove "+a.path)
	}
	if err := os.Remove(filepath.Join(parent, installLockName)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return errDefinition.With(err, "remove "+filepath.Join(parent, installLockName))
	}
	if err := os.Remove(parent); err != nil && !errors.Is(err, fs.ErrNotExist) && !isNotEmpty(parent) {
		return errDefinition.With(err, "remove "+parent)
	}
	return nil
}

const installLockName = ".install.lock"

// openInstallLock opens the install lock file; tests replace it.
var openInstallLock = security.OpenLockFile

// lockInstall takes the install lock in dir without waiting; a held lock is
// errInstallBusy. uninstall unlinks the lock file while holding it, so a lock
// taken on a file no longer at path is dropped and taken again, and a missing
// dir means an uninstall removed it: busy.
func lockInstall(dir string) (unlock func(), err error) {
	path := filepath.Join(dir, installLockName)
	busy := errInstallBusy.With(nil, "run it again once the other one finishes")
	for range 3 {
		f, err := openInstallLock(path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, busy
		}
		if err != nil {
			return nil, errDefinition.With(err, "open "+path)
		}
		held, err := security.TryLockFile(f)
		if err != nil || !held {
			_ = f.Close()
			if err != nil {
				return nil, errDefinition.With(err, "lock "+path)
			}
			return nil, busy
		}
		release := func() {
			_ = security.UnlockFile(f)
			_ = f.Close()
		}
		if lockedAtPath(f, path) {
			return release, nil
		}
		release()
	}
	return nil, busy
}

// lockedAtPath reports whether f is still the file at path.
func lockedAtPath(f *os.File, path string) bool {
	held, err := f.Stat()
	if err != nil {
		return false
	}
	current, err := os.Lstat(path)
	return err == nil && os.SameFile(held, current)
}

// isNotEmpty reports whether dir still holds an entry.
func isNotEmpty(dir string) bool {
	entries, err := os.ReadDir(dir)
	return err == nil && len(entries) > 0
}

// removeLeftovers deletes staging directories an interrupted install left.
func removeLeftovers(parent string) {
	leftovers, _ := filepath.Glob(filepath.Join(parent, ".staged-*"))
	for _, d := range leftovers {
		_ = os.RemoveAll(d)
	}
}

// ensureDir creates dir as a real directory owned by a.uid:a.gid, mode 0755,
// and takes over one that exists.
func (a sessionApp) ensureDir(dir string) error {
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return errDefinition.With(err, "create "+dir)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return errDefinition.With(err, "inspect "+dir)
	}
	if !fi.IsDir() {
		return errDefinition.With(nil, dir+" is not a directory")
	}
	return a.own(dir, 0o755)
}

// own sets path's owner to a.uid:a.gid and its mode to perm.
func (a sessionApp) own(path string, perm fs.FileMode) error {
	if err := os.Lchown(path, a.uid, a.gid); err != nil {
		return errDefinition.With(err, "set the owner of "+path)
	}
	if err := os.Chmod(path, perm); err != nil {
		return errDefinition.With(err, "set the mode of "+path)
	}
	return nil
}

// copyTree copies the bundle at src to dst: directories 0755, executables
// 0755, other files 0644, every entry owned by a.uid:a.gid. A bundle holds
// only directories and regular files; anything else is refused.
func (a sessionApp) copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return errDefinition.With(err, "read "+p)
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return errDefinition.With(err, "read "+p)
		}
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			if err := os.Mkdir(target, 0o700); err != nil {
				return errDefinition.With(err, "stage "+target)
			}
			return a.own(target, 0o755)
		case d.Type().IsRegular():
			info, err := d.Info()
			if err != nil {
				return errDefinition.With(err, "read "+p)
			}
			perm := fs.FileMode(0o644)
			if info.Mode()&0o111 != 0 {
				perm = 0o755
			}
			if err := copyFile(p, target); err != nil {
				return err
			}
			return a.own(target, perm)
		default:
			return errAppInvalid.With(nil, fmt.Sprintf("%s is not a regular file or directory", p))
		}
	})
}

// copyFile copies src to a new file dst, created owner-only until own runs.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return errDefinition.With(err, "read "+src)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errDefinition.With(err, "stage "+dst)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return errDefinition.With(err, "stage "+dst)
	}
	if err := out.Close(); err != nil {
		return errDefinition.With(err, "stage "+dst)
	}
	return nil
}

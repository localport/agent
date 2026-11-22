package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/localport/agent/internal/errcode"
)

// testApp is a sessionApp installing under a temporary directory as the
// current user. verify nil accepts every bundle.
func testApp(t *testing.T, verify func(context.Context, string) error) sessionApp {
	t.Helper()
	if verify == nil {
		verify = func(context.Context, string) error { return nil }
	}
	return sessionApp{
		path:   filepath.Join(t.TempDir(), "Localport", AppName),
		uid:    os.Getuid(),
		gid:    os.Getgid(),
		verify: verify,
	}
}

// testAppExe is a CLI path beside a bundle whose launcher holds "v1".
func testAppExe(t *testing.T) string {
	t.Helper()
	return writeTestApp(t, t.TempDir(), "v1")
}

// writeTestApp writes dir/localport and dir/Localport.app with a launcher
// holding version, and returns the CLI path.
func writeTestApp(t *testing.T, dir, version string) string {
	t.Helper()
	bundle := filepath.Join(dir, AppName)
	if err := os.MkdirAll(filepath.Join(bundle, "Contents", "MacOS"), 0o777); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(bundle, "Contents", "Info.plist"), "<plist/>")
	if err := os.WriteFile(filepath.Join(bundle, appExecutable), []byte(version), 0o777); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(dir, "localport")
	writeFile(t, cli, "cli")
	return cli
}

func installedVersion(t *testing.T, a sessionApp) string {
	t.Helper()
	b, err := os.ReadFile(a.executable())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func assertNoLeftovers(t *testing.T, a sessionApp) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(a.path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != AppName && e.Name() != installLockName {
			t.Errorf("%s left in the app directory", e.Name())
		}
	}
}

// An install or uninstall while another install holds the lock is refused
// at once (AG161) and leaves the running install's stage alone; the running
// install then completes.
func TestSessionAppInstallsAreSerialized(t *testing.T) {
	unixInitOnly(t)
	verifying, release := make(chan struct{}), make(chan struct{})
	first := testApp(t, func(context.Context, string) error {
		close(verifying)
		<-release
		return nil
	})
	done := make(chan error, 1)
	go func() { done <- first.install(context.Background(), testAppExe(t)) }()
	<-verifying
	stages, _ := filepath.Glob(filepath.Join(filepath.Dir(first.path), ".staged-*"))
	if len(stages) != 1 {
		t.Fatalf("stages while the first install verifies: %v", stages)
	}

	second := first
	second.verify = func(context.Context, string) error { return nil }
	if err := second.install(context.Background(), testAppExe(t)); !errors.Is(err, errInstallBusy) {
		t.Fatalf("concurrent install = %v, want errInstallBusy", err)
	}
	if err := second.uninstall(); !errors.Is(err, errInstallBusy) {
		t.Fatalf("concurrent uninstall = %v, want errInstallBusy", err)
	}
	if _, err := os.Stat(stages[0]); err != nil {
		t.Fatalf("the running install's stage is gone: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first install = %v", err)
	}
	if got := installedVersion(t, first); got != "v1" {
		t.Fatalf("installed launcher = %q, want v1", got)
	}
	assertNoLeftovers(t, first)
}

// A lock held on a lock file an uninstall unlinked excludes nobody: it is not
// taken as the install lock. With the directory gone, an install is busy.
func TestInstallLockFollowsTheFileAtItsPath(t *testing.T) {
	unixInitOnly(t)
	dir := t.TempDir()
	path := filepath.Join(dir, installLockName)
	orphan, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer orphan.Close()
	if !lockedAtPath(orphan, path) {
		t.Fatal("the file at its path is not recognized")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if lockedAtPath(orphan, path) {
		t.Fatal("an unlinked lock file counts as the lock")
	}
	unlock, err := lockInstall(dir)
	if err != nil {
		t.Fatalf("lock after the unlink = %v", err)
	}
	unlock()
	if _, err := lockInstall(filepath.Join(dir, "gone")); !errors.Is(err, errInstallBusy) {
		t.Fatalf("lock in a removed directory = %v, want errInstallBusy", err)
	}
}

// The interleaving uninstall causes: an install opens the lock file, uninstall
// unlinks it and another install creates a new one before the lock is taken.
// lockInstall drops the lock on the unlinked file and takes the one at the
// path, so a further install is busy.
func TestInstallLockRetriesAfterAnUnlink(t *testing.T) {
	unixInitOnly(t)
	dir := t.TempDir()
	opens := 0
	saved := openInstallLock
	openInstallLock = func(p string) (*os.File, error) {
		opens++
		f, err := saved(p)
		if err == nil && opens == 1 {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			replacement, err := saved(p)
			if err != nil {
				t.Fatal(err)
			}
			_ = replacement.Close()
		}
		return f, err
	}
	t.Cleanup(func() { openInstallLock = saved })

	unlock, err := lockInstall(dir)
	if err != nil {
		t.Fatalf("lockInstall = %v", err)
	}
	defer unlock()
	if opens != 2 {
		t.Fatalf("%d opens, want a retry after the unlinked lock", opens)
	}
	if _, err := lockInstall(dir); !errors.Is(err, errInstallBusy) {
		t.Fatalf("a second install = %v, want errInstallBusy: the lock must be on the file at the path", err)
	}
}

// An uninstall whose directory a concurrent one removed is done, not busy.
func TestConcurrentUninstallIsDone(t *testing.T) {
	unixInitOnly(t)
	a := testApp(t, nil)
	if err := a.install(context.Background(), testAppExe(t)); err != nil {
		t.Fatal(err)
	}
	saved := openInstallLock
	openInstallLock = func(p string) (*os.File, error) {
		if err := os.RemoveAll(filepath.Dir(p)); err != nil {
			t.Fatal(err)
		}
		return saved(p)
	}
	t.Cleanup(func() { openInstallLock = saved })
	if err := a.uninstall(); err != nil {
		t.Fatalf("uninstall after a concurrent one = %v, want nil", err)
	}
}

// A Localport.app beside the CLI that is not a directory is named as such.
func TestSessionAppNotAFolder(t *testing.T) {
	unixInitOnly(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, AppName), "not a bundle")
	_, err := appBeside(filepath.Join(dir, "localport"))
	var coded *errcode.Error
	if !errors.As(err, &coded) || coded.Code != errcode.SessionAppInvalid || !strings.Contains(coded.Detail, "is not a folder") {
		t.Fatalf("appBeside = %v, want AG014 naming a file that is not a folder", err)
	}
}

// The installed bundle is a copy of the one beside the CLI, verified while
// staged, writable by the owner only; an update replaces it whole.
func TestSessionAppInstallsAndReplaces(t *testing.T) {
	unixInitOnly(t)
	var verified []string
	a := testApp(t, func(_ context.Context, bundle string) error {
		verified = append(verified, bundle)
		return nil
	})
	dir := t.TempDir()
	exe := writeTestApp(t, dir, "v1")
	if err := a.install(context.Background(), exe); err != nil {
		t.Fatal(err)
	}
	if got := installedVersion(t, a); got != "v1" {
		t.Fatalf("installed launcher = %q, want v1", got)
	}
	for path, want := range map[string]os.FileMode{
		filepath.Dir(a.path):              0o755,
		a.path:                            0o755,
		filepath.Join(a.path, "Contents"): 0o755,
		a.executable():                    0o755,
		filepath.Join(a.path, "Contents/Info.plist"): 0o644,
	} {
		fi, err := os.Lstat(path)
		if err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: %v, %v; want mode %v", path, fi, err, want)
		}
	}
	if len(verified) != 1 || verified[0] == a.path || filepath.Base(verified[0]) != AppName ||
		!strings.HasPrefix(verified[0], filepath.Join(filepath.Dir(a.path), ".staged-")) {
		t.Fatalf("verified %q, want the staged copy only", verified)
	}

	writeTestApp(t, dir, "v2")
	if err := a.install(context.Background(), exe); err != nil {
		t.Fatal(err)
	}
	if got := installedVersion(t, a); got != "v2" {
		t.Fatalf("updated launcher = %q, want v2", got)
	}
	assertNoLeftovers(t, a)
}

// Every refusal and failure before the new bundle is in place keeps the old one.
func TestSessionAppFailureKeepsTheInstalledApp(t *testing.T) {
	unixInitOnly(t)
	for name, c := range map[string]struct {
		verify  func(a sessionApp) func(context.Context, string) error
		prepare func(t *testing.T, dir string)
		want    error
		// unwritable is a case that relies on a read-only directory, which
		// root ignores; its staging directory stays until the next install.
		unwritable bool
	}{
		"signature refused": {
			verify: func(sessionApp) func(context.Context, string) error {
				return func(context.Context, string) error { return errAppInvalid.With(nil, "unsigned") }
			},
			want: errAppInvalid,
		},
		"symlink in the bundle": {
			prepare: func(t *testing.T, dir string) {
				if err := os.Symlink("/etc/hosts", filepath.Join(dir, AppName, "Contents", "link")); err != nil {
					t.Fatal(err)
				}
			},
			want: errAppInvalid,
		},
		// The app directory refuses the exchange.
		"exchange refused by the directory": {
			verify: func(a sessionApp) func(context.Context, string) error {
				return func(context.Context, string) error {
					return os.Chmod(filepath.Dir(a.path), 0o555)
				}
			},
			want:       errDefinition,
			unwritable: true,
		},
		// The staged bundle is gone when the exchange runs, so it fails and
		// leaves the installed bundle in place.
		"staged bundle gone before the exchange": {
			verify: func(sessionApp) func(context.Context, string) error {
				return func(_ context.Context, bundle string) error { return os.RemoveAll(bundle) }
			},
			want: errDefinition,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if c.unwritable && os.Getuid() == 0 {
				t.Skip("root writes to a read-only directory")
			}
			a := testApp(t, nil)
			dir := t.TempDir()
			exe := writeTestApp(t, dir, "v1")
			if err := a.install(context.Background(), exe); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(filepath.Dir(a.path), 0o755) })
			writeTestApp(t, dir, "v2")
			if c.prepare != nil {
				c.prepare(t, dir)
			}
			if c.verify != nil {
				a.verify = c.verify(a)
			}
			if err := a.install(context.Background(), exe); !errors.Is(err, c.want) {
				t.Fatalf("install = %v, want %v", err, c.want)
			}
			if err := os.Chmod(filepath.Dir(a.path), 0o755); err != nil {
				t.Fatal(err)
			}
			if got := installedVersion(t, a); got != "v1" {
				t.Fatalf("installed launcher = %q after a failed update, want v1", got)
			}
			if c.unwritable {
				removeLeftovers(filepath.Dir(a.path))
			}
			assertNoLeftovers(t, a)
		})
	}
}

// Without a bundle beside the CLI nothing is created.
func TestSessionAppMissingIsRefused(t *testing.T) {
	unixInitOnly(t)
	a := testApp(t, nil)
	if err := a.install(context.Background(), filepath.Join(t.TempDir(), "localport")); !errors.Is(err, errAppInvalid) {
		t.Fatalf("install = %v, want errAppInvalid", err)
	}
	if _, err := os.Lstat(filepath.Dir(a.path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the app directory was created: %v", err)
	}
}

// CheckApp refuses a missing bundle and one verify refuses, writing nothing.
func TestLaunchdCheckApp(t *testing.T) {
	unixInitOnly(t)
	l := newLaunchd(t, &recorder{})
	if err := l.CheckApp(context.Background(), filepath.Join(t.TempDir(), "localport")); !errors.Is(err, errAppInvalid) {
		t.Fatalf("missing app = %v, want errAppInvalid", err)
	}
	exe := testAppExe(t)
	if err := l.CheckApp(context.Background(), exe); err != nil {
		t.Fatalf("accepted app = %v", err)
	}
	l.app.verify = func(context.Context, string) error { return errAppInvalid }
	if err := l.CheckApp(context.Background(), exe); !errors.Is(err, errAppInvalid) {
		t.Fatalf("unsigned app = %v, want errAppInvalid", err)
	}
	if _, err := os.Lstat(filepath.Dir(l.app.path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("CheckApp created the app directory: %v", err)
	}
}

// The launcher daemon runs the installed bundle, not the copy beside the CLI.
func TestLaunchdInstallRunsTheInstalledApp(t *testing.T) {
	unixInitOnly(t)
	r := &recorder{fail: notLoaded(LaunchdLabel, LaunchdLauncherLabel)}
	l := newLaunchd(t, r)
	if err := l.Install(context.Background(), testAppExe(t)); err != nil {
		t.Fatal(err)
	}
	plist, err := os.ReadFile(filepath.Join(filepath.Dir(l.plistPath), LaunchdLauncherLabel+".plist"))
	if err != nil {
		t.Fatal(err)
	}
	if strs := plistStrings(t, plist); !slices.Contains(strs, l.app.executable()) {
		t.Fatalf("launcher plist runs none of %q, want %s", strs, l.app.executable())
	}
	if got := installedVersion(t, l.app); got != "v1" {
		t.Fatalf("installed launcher = %q, want v1", got)
	}
}

// A refused bundle stops the install before any plist is written or any
// daemon is touched.
func TestLaunchdInstallStopsOnARefusedApp(t *testing.T) {
	unixInitOnly(t)
	r := &recorder{fail: notLoaded(LaunchdLabel, LaunchdLauncherLabel)}
	l := newLaunchd(t, r)
	l.app.verify = func(context.Context, string) error { return errAppInvalid }
	if err := l.Install(context.Background(), testAppExe(t)); !errors.Is(err, errAppInvalid) {
		t.Fatalf("Install = %v, want errAppInvalid", err)
	}
	for _, p := range l.plists() {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s written: %v", p, err)
		}
	}
	if len(r.calls) > 0 {
		t.Fatalf("commands ran: %q", r.calls)
	}
}

func TestAppRequirement(t *testing.T) {
	if req, err := appRequirement(""); err != nil || req != `identifier "io.localport.session"` {
		t.Errorf("ad-hoc requirement = %q, %v", req, err)
	}
	const sha = "fe8dd57e9c2c72b26bee46df1a0769ab217516ea"
	if req, err := appRequirement(sha); err != nil || req != `identifier "io.localport.session" and certificate leaf = H"`+sha+`"` {
		t.Errorf("release requirement = %q, %v", req, err)
	}
	for _, bad := range []string{"FE8DD57E9C2C72B26BEE46DF1A0769AB217516EA", sha[:39], sha + `" or anchor trusted`} {
		if _, err := appRequirement(bad); !errors.Is(err, errAppInvalid) {
			t.Errorf("appRequirement(%q) = %v, want errAppInvalid", bad, err)
		}
	}
}

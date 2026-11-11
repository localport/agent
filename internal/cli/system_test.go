package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeInstallHost is a machine with two owned services, an uninstall entry
// and a machine Path, each failure injectable by name.
type fakeInstallHost struct {
	notElevated bool
	dirErr      error
	lockErr     error
	locks       int

	// services: the definition the snapshot records, which restore writes
	// back, and the names running.
	definition string
	existed    bool
	running    []string
	installed  []string
	deleted    int
	restores   int
	purges     int

	key        json.RawMessage
	path       string
	expandable bool
	broadcasts int
	queued     []string
	warnings   []string

	// fail names the operations that fail: stop, start, restore, install,
	// delete, key (restoring or deleting the entry), keywrite, path, purge,
	// foreign.
	fail    map[string]bool
	foreign []string
	// onKeyWrite runs after a successful uninstall entry write.
	onKeyWrite func()
}

var errInjected = errors.New("injected failure")

func (f *fakeInstallHost) failing(op string) error {
	if f.fail[op] {
		return errInjected
	}
	return nil
}

func (f *fakeInstallHost) elevated() bool                 { return !f.notElevated }
func (f *fakeInstallHost) prepareInstallDir(string) error { return f.dirErr }
func (f *fakeInstallHost) lockServiceConfig(context.Context) (func(), bool, error) {
	if f.lockErr != nil {
		return nil, false, f.lockErr
	}
	f.locks++
	return func() {}, false, nil
}
func (f *fakeInstallHost) snapshotServices() (json.RawMessage, []string, bool, error) {
	raw, _ := json.Marshal(f.definition)
	return raw, slices.Clone(f.running), f.existed, nil
}
func (f *fakeInstallHost) stopServices(context.Context) ([]string, error) {
	if err := f.failing("stop"); err != nil {
		return nil, err
	}
	stopped := f.running
	f.running = nil
	return stopped, nil
}
func (f *fakeInstallHost) startServices(_ context.Context, names []string) error {
	if err := f.failing("start"); err != nil {
		return err
	}
	for _, n := range names {
		if !slices.Contains(f.running, n) {
			f.running = append(f.running, n)
		}
	}
	return nil
}
func (f *fakeInstallHost) restoreServices(_ context.Context, raw json.RawMessage) error {
	f.restores++
	if err := f.failing("restore"); err != nil {
		return err
	}
	f.running = nil
	return json.Unmarshal(raw, &f.definition)
}
func (f *fakeInstallHost) installServices(_ context.Context, exe string) error {
	f.installed = append(f.installed, exe)
	// A failing install has already rewritten the definitions, as a
	// failure partway through `service install` would.
	f.definition = "new:" + exe
	if err := f.failing("install"); err != nil {
		return err
	}
	f.running = []string{"localport-session", "localport-device"}
	return nil
}
func (f *fakeInstallHost) deleteServices(context.Context) error {
	if err := f.failing("delete"); err != nil {
		return err
	}
	f.deleted++
	f.definition, f.existed, f.running = "", false, nil
	return nil
}
func (f *fakeInstallHost) purge(context.Context) error { f.purges++; return f.failing("purge") }
func (f *fakeInstallHost) foreignServicesIn(string) ([]string, error) {
	return f.foreign, f.failing("foreign")
}
func (f *fakeInstallHost) readUninstallKey() (json.RawMessage, error) { return f.key, nil }
func (f *fakeInstallHost) restoreUninstallKey(raw json.RawMessage) error {
	if err := f.failing("key"); err != nil {
		return err
	}
	if raw == nil && f.fail["keydelete"] {
		return errInjected
	}
	f.key = raw
	return nil
}
func (f *fakeInstallHost) writeUninstallKey(dir, version string, _ uint32) error {
	if err := f.failing("keywrite"); err != nil {
		return err
	}
	f.key = json.RawMessage(`"` + version + `@` + filepath.ToSlash(dir) + `"`)
	if f.onKeyWrite != nil {
		f.onKeyWrite()
	}
	return nil
}
func (f *fakeInstallHost) readPath() (string, bool, error) { return f.path, f.expandable, nil }
func (f *fakeInstallHost) writePath(v string, expandable bool) error {
	if err := f.failing("path"); err != nil {
		return err
	}
	f.path, f.expandable = v, expandable
	return nil
}
func (f *fakeInstallHost) broadcastEnvironment() error { f.broadcasts++; return nil }
func (f *fakeInstallHost) expand(s string) string {
	return strings.ReplaceAll(s, "%SystemRoot%", `C:\Windows`)
}
func (f *fakeInstallHost) deleteAtReboot(p string) error { f.queued = append(f.queued, p); return nil }
func (f *fakeInstallHost) warn(msg string)               { f.warnings = append(f.warnings, msg) }

// installed is a machine running release v1 from dir with both services up.
func installedHost(t *testing.T) (*fakeInstallHost, string) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range productFiles {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("v1"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &fakeInstallHost{
		definition: "v1", existed: true, running: []string{"localport-session", "localport-device"},
		key: json.RawMessage(`"1.0.0"`), path: `C:\Windows;` + dir, expandable: true,
		fail: map[string]bool{},
	}, dir
}

const testTxn = "nsA1b2.tmp"

// stageRelease runs begin and extracts release into its staging directory,
// as NSIS does.
func stageRelease(t *testing.T, h *fakeInstallHost, dir, release string) {
	t.Helper()
	if err := runSystemSteps(context.Background(), h, "v2.0.0", []string{"begin", dir, testTxn}); err != nil {
		t.Fatalf("begin = %v", err)
	}
	for _, name := range productFiles {
		if err := os.WriteFile(filepath.Join(dir, txnRoot, testTxn, "staging", name), []byte(release), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func readProduct(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	for _, name := range productFiles {
		raw, _ := os.ReadFile(filepath.Join(dir, name))
		out = append(out, string(raw))
	}
	return out
}

func allOf(n int, v string) []string { return slices.Repeat([]string{v}, n) }

func assertNoTransaction(t *testing.T, dir string) {
	t.Helper()
	if entries, _ := os.ReadDir(filepath.Join(dir, txnRoot)); len(entries) != 0 {
		t.Fatalf("transaction directories left: %v", entries)
	}
}

// Every step refuses unless elevated, before it does anything.
func TestSystemStepsRefuseWithoutElevation(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{{"begin", dir, testTxn}, {"apply", dir, testTxn}, {"rollback", dir}, {"uninstall", dir}} {
		h := &fakeInstallHost{notElevated: true}
		if err := runSystemSteps(context.Background(), h, "v2", args); !errors.Is(err, errInstallerNotElevated) {
			t.Errorf("%v = %v, want errInstallerNotElevated", args, err)
		}
		if h.locks != 0 {
			t.Errorf("%v took the lock without elevation", args)
		}
	}
}

// Bad arguments and unknown steps carry the installer step code.
func TestSystemStepErrorsCarryACode(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{nil, {"begin", dir}, {"begin", "relative", testTxn}, {"begin", dir, "../x"}, {"apply", dir, "ns.tmp/.."}, {"rollback"}, {"bogus", dir, testTxn}} {
		if err := runSystemSteps(context.Background(), &fakeInstallHost{}, "v2", args); !errors.Is(err, errInstallerStepInvalid) {
			t.Errorf("%v = %v, want errInstallerStepInvalid", args, err)
		}
	}
}

// begin refuses an unsafe directory and a busy service configuration lock.
func TestSystemBeginRefuses(t *testing.T) {
	dir := t.TempDir()
	unsafe := errors.New("Users can add files")
	if err := runSystemSteps(context.Background(), &fakeInstallHost{dirErr: unsafe}, "v2", []string{"begin", dir, testTxn}); !errors.Is(err, errInstallDirUnsafe) || !errors.Is(err, unsafe) {
		t.Fatalf("begin = %v, want errInstallDirUnsafe", err)
	}
	assertNoTransaction(t, dir)
	busy := errors.Join(errServiceConfigBusy, errors.New("held"))
	if err := runSystemSteps(context.Background(), &fakeInstallHost{lockErr: busy}, "v2", []string{"apply", dir, testTxn}); !errors.Is(err, errServiceConfigBusy) {
		t.Fatalf("apply with the lock held = %v", err)
	}
}

// A successful upgrade replaces every product file, records the entry,
// leaves Path alone when it already holds the directory, re-registers the
// services for the installed exe and leaves no transaction behind.
func TestSystemApplyUpgrades(t *testing.T) {
	h, dir := installedHost(t)
	stageRelease(t, h, dir, "v2")
	if err := runSystemSteps(context.Background(), h, "v2.0.0", []string{"apply", dir, testTxn}); err != nil {
		t.Fatal(err)
	}
	if got := readProduct(t, dir); !slices.Equal(got, allOf(len(productFiles), "v2")) {
		t.Fatalf("product files = %v", got)
	}
	if !slices.Equal(h.installed, []string{filepath.Join(dir, "localport.exe")}) || len(h.running) != 2 {
		t.Fatalf("services installed %v, running %v", h.installed, h.running)
	}
	if !strings.HasPrefix(string(h.key), `"2.0.0@`) || h.path != `C:\Windows;`+dir || h.broadcasts != 0 {
		t.Fatalf("key %s, path %q, broadcasts %d", h.key, h.path, h.broadcasts)
	}
	assertNoTransaction(t, dir)
}

// A first install adds dir to Path (kept REG_SZ when it was) and announces
// it once; with no services it registers none.
func TestSystemApplyFirstInstall(t *testing.T) {
	dir := t.TempDir()
	h := &fakeInstallHost{path: `C:\Tools`, fail: map[string]bool{}}
	stageRelease(t, h, dir, "v2")
	if err := runSystemSteps(context.Background(), h, "v2.0.0", []string{"apply", dir, testTxn}); err != nil {
		t.Fatal(err)
	}
	if h.path != `C:\Tools;`+dir || h.expandable || h.broadcasts != 1 || len(h.installed) != 0 {
		t.Fatalf("path %q (expandable %v), broadcasts %d, installed %v", h.path, h.expandable, h.broadcasts, h.installed)
	}
	assertNoTransaction(t, dir)
}

// A failure at any action puts the machine back as it was: every product
// file from v1, the entry, Path, the service definitions, and the services
// that were running started again.
func TestSystemApplyRollsBackEveryAction(t *testing.T) {
	for _, op := range []string{"stop", "move", "key", "path", "install"} {
		t.Run(op, func(t *testing.T) {
			h, dir := installedHost(t)
			h.path = `C:\Windows` // so the apply adds dir and its undo is exercised
			stageRelease(t, h, dir, "v2")
			want := map[string]error{"stop": errServicesNotStopped, "move": errInstallNotCommitted, "key": errUninstallEntryNotSet, "path": errMachinePathNotSet, "install": errServicesNotRestored}[op]
			if op == "key" {
				op = "keywrite"
			}
			if op == "move" {
				// The second file cannot be set aside: a directory holds its
				// backup name.
				if err := os.MkdirAll(filepath.Join(dir, txnRoot, testTxn, "backup", productFiles[1], "x"), 0o755); err != nil {
					t.Fatal(err)
				}
			} else {
				h.fail[op] = true
			}
			err := runSystemSteps(context.Background(), h, "v2.0.0", []string{"apply", dir, testTxn})
			if !errors.Is(err, want) || errors.Is(err, errInstallMixed) {
				t.Fatalf("apply = %v, want %v", err, want)
			}
			if got := readProduct(t, dir); !slices.Equal(got, allOf(len(productFiles), "v1")) {
				t.Fatalf("product files after rollback = %v", got)
			}
			if h.definition != "v1" || string(h.key) != `"1.0.0"` || h.path != `C:\Windows` {
				t.Fatalf("after rollback: definition %q, key %s, path %q", h.definition, h.key, h.path)
			}
			if op != "stop" && !slices.Contains(h.running, "localport-device") {
				t.Fatalf("running after rollback = %v, want the services that ran", h.running)
			}
			if op == "move" {
				// The test's own blocker stays; nothing else does.
				return
			}
			assertNoTransaction(t, dir)
		})
	}
}

// A rollback that cannot finish keeps the journal and reports AG090; the
// next run retries it before anything else.
func TestSystemRollbackFailureIsRetried(t *testing.T) {
	h, dir := installedHost(t)
	stageRelease(t, h, dir, "v2")
	h.fail["install"], h.fail["restore"] = true, true
	if err := runSystemSteps(context.Background(), h, "v2.0.0", []string{"apply", dir, testTxn}); !errors.Is(err, errInstallMixed) {
		t.Fatalf("apply = %v, want errInstallMixed", err)
	}
	if _, err := os.Stat(filepath.Join(dir, txnRoot, testTxn, journalFile)); err != nil {
		t.Fatalf("journal after a failed rollback: %v", err)
	}
	h.fail["restore"] = false
	if err := runSystemSteps(context.Background(), h, "v2.0.0", []string{"rollback", dir}); err != nil {
		t.Fatal(err)
	}
	if got := readProduct(t, dir); !slices.Equal(got, allOf(len(productFiles), "v1")) || h.definition != "v1" {
		t.Fatalf("after the retried rollback: files %v, definition %q", got, h.definition)
	}
	assertNoTransaction(t, dir)
}

// writeJournal leaves transaction txn as a run killed at phase left it:
// localport.exe already set aside and v2 in its place.
func writeJournal(t *testing.T, dir, phase string) {
	t.Helper()
	txnDir := filepath.Join(dir, txnRoot, testTxn)
	for _, d := range []string{"staging", "backup"} {
		if err := os.MkdirAll(filepath.Join(txnDir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	current := filepath.Join(dir, "localport.exe")
	backup := filepath.Join(txnDir, "backup", "localport.exe")
	if err := os.Rename(current, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(current, []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap, _ := json.Marshal("v1")
	j := journal{Op: opInstall, Txn: testTxn, Phase: phase, Services: snap, Running: []string{"localport-device"}, Key: json.RawMessage(`"1.0.0"`), KeyFound: true,
		Actions: []txnAction{
			{Kind: actStop, Names: []string{"localport-device"}, Done: true},
			{Kind: actMove, From: current, To: backup, Done: true},
			{Kind: actMove, From: filepath.Join(txnDir, "staging", "localport.exe"), To: current, Done: true},
		}}
	raw, _ := json.Marshal(j)
	if err := os.WriteFile(filepath.Join(txnDir, journalFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// An interrupted transaction is resolved by the next run: one applying is
// rolled back, one committed is finished, one begun is dropped.
func TestSystemRecoversAnInterruptedTransaction(t *testing.T) {
	t.Run("applying", func(t *testing.T) {
		h, dir := installedHost(t)
		h.running = nil
		writeJournal(t, dir, phaseApplying)
		if err := runSystemSteps(context.Background(), h, "v2", []string{"begin", dir, "nsNext.tmp"}); err != nil {
			t.Fatal(err)
		}
		if got := readProduct(t, dir); got[0] != "v1" || !slices.Contains(h.running, "localport-device") {
			t.Fatalf("after recovery: localport.exe %q, running %v", got[0], h.running)
		}
		if _, err := os.Stat(filepath.Join(dir, txnRoot, testTxn)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("interrupted transaction left: %v", err)
		}
	})
	t.Run("committed", func(t *testing.T) {
		h, dir := installedHost(t)
		writeJournal(t, dir, phaseCommitted)
		if err := runSystemSteps(context.Background(), h, "v2", []string{"rollback", dir}); err != nil {
			t.Fatal(err)
		}
		if got := readProduct(t, dir); got[0] != "v2" {
			t.Fatalf("a committed transaction was undone: localport.exe %q", got[0])
		}
		assertNoTransaction(t, dir)
	})
	t.Run("begun", func(t *testing.T) {
		h, dir := installedHost(t)
		stageRelease(t, h, dir, "v2")
		if err := runSystemSteps(context.Background(), h, "v2", []string{"rollback", dir}); err != nil {
			t.Fatal(err)
		}
		if got := readProduct(t, dir); !slices.Equal(got, allOf(len(productFiles), "v1")) {
			t.Fatalf("product files = %v", got)
		}
		assertNoTransaction(t, dir)
	})
}

// A backup Windows will not delete (an image still running) is queued for
// deletion at reboot and blocks nothing.
func TestSystemQueuesABackupItCannotDelete(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root deletes from a read-only directory")
	}
	h, dir := installedHost(t)
	stageRelease(t, h, dir, "v2")
	backup := filepath.Join(dir, txnRoot, testTxn, "backup")
	// The rename into the backup directory happens before it turns
	// read-only, so the apply's own moves are unaffected.
	h.afterMovesHook(t, backup)
	if err := runSystemSteps(context.Background(), h, "v2.0.0", []string{"apply", dir, testTxn}); err != nil {
		t.Fatal(err)
	}
	if len(h.queued) == 0 || !strings.HasPrefix(h.queued[0], backup) {
		t.Fatalf("queued for reboot = %v, want the backups", h.queued)
	}
	stageNext := &fakeInstallHost{fail: map[string]bool{}, path: h.path}
	if err := runSystemSteps(context.Background(), stageNext, "v3", []string{"begin", dir, "nsNext.tmp"}); err != nil {
		t.Fatalf("the next begin with a queued backup = %v", err)
	}
}

// afterMovesHook makes the backup directory read-only once the uninstall
// entry is written, the action after the last move.
func (f *fakeInstallHost) afterMovesHook(t *testing.T, backup string) {
	t.Helper()
	f.onKeyWrite = func() {
		if err := os.Chmod(backup, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(backup, 0o700) })
	}
}

// Uninstall removes services, Path entry, entry and files, then purges; a
// foreign service inside the directory refuses it; a failure rolls back.
func TestSystemUninstall(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		h, dir := installedHost(t)
		if err := runSystemSteps(context.Background(), h, "v1", []string{"uninstall", dir, "--purge"}); err != nil {
			t.Fatal(err)
		}
		if h.deleted != 1 || h.key != nil || h.path != `C:\Windows` || h.purges != 1 || h.broadcasts != 1 {
			t.Fatalf("deleted %d, key %s, path %q, purges %d, broadcasts %d", h.deleted, h.key, h.path, h.purges, h.broadcasts)
		}
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("install directory after uninstall: %v", err)
		}
	})
	t.Run("foreign", func(t *testing.T) {
		h, dir := installedHost(t)
		h.foreign = []string{"OtherSvc"}
		if err := runSystemSteps(context.Background(), h, "v1", []string{"uninstall", dir}); !errors.Is(err, errForeignServiceInDir) || h.deleted != 0 {
			t.Fatalf("uninstall = %v, deleted %d", err, h.deleted)
		}
	})
	t.Run("no purge", func(t *testing.T) {
		h, dir := installedHost(t)
		if err := runSystemSteps(context.Background(), h, "v1", []string{"uninstall", dir}); err != nil || h.purges != 0 {
			t.Fatalf("uninstall = %v, purges %d", err, h.purges)
		}
	})
	t.Run("rollback restores Path exactly", func(t *testing.T) {
		h, dir := installedHost(t)
		h.path = `C:\Windows;` + dir + `;C:\Tools`
		h.fail["keydelete"] = true
		if err := runSystemSteps(context.Background(), h, "v1", []string{"uninstall", dir}); !errors.Is(err, errUninstallNotPrepared) {
			t.Fatalf("uninstall = %v", err)
		}
		if h.path != `C:\Windows;`+dir+`;C:\Tools` || string(h.key) != `"1.0.0"` {
			t.Fatalf("after rollback: path %q, key %s", h.path, h.key)
		}
	})
	t.Run("rollback", func(t *testing.T) {
		h, dir := installedHost(t)
		h.fail["path"] = true
		err := runSystemSteps(context.Background(), h, "v1", []string{"uninstall", dir, "--purge"})
		if !errors.Is(err, errUninstallNotPrepared) {
			t.Fatalf("uninstall = %v", err)
		}
		if got := readProduct(t, dir); !slices.Equal(got, allOf(len(productFiles), "v1")) || h.definition != "v1" || h.path != `C:\Windows;`+dir || h.purges != 0 {
			t.Fatalf("after rollback: files %v, definition %q, path %q, purges %d", got, h.definition, h.path, h.purges)
		}
		if !slices.Contains(h.running, "localport-device") {
			t.Fatalf("running after rollback = %v", h.running)
		}
		assertNoTransaction(t, dir)
	})
}

// Path edits keep every other entry and the value's type, match case- and
// separator-insensitively and after expansion, and are idempotent.
func TestSystemPathEdits(t *testing.T) {
	expand := (&fakeInstallHost{}).expand
	dir := `C:\Program Files\Localport`
	long := strings.Repeat(`C:\x;`, 2000) + `%SystemRoot%\system32`
	for _, tc := range []struct{ name, op, before, after string }{
		{"add", "add", `%SystemRoot%\system32;C:\Tools`, `%SystemRoot%\system32;C:\Tools;` + dir},
		{"re-add", "add", `C:\Tools;` + strings.ToUpper(dir) + `\`, `C:\Tools;` + strings.ToUpper(dir) + `\`},
		{"add to empty", "add", ``, dir},
		{"add after trailing separator", "add", `C:\Tools;`, `C:\Tools;` + dir},
		{"remove", "remove", `C:\Tools;` + dir + `;%SystemRoot%`, `C:\Tools;%SystemRoot%`},
		{"remove absent", "remove", `C:\Tools`, `C:\Tools`},
		{"long value kept", "add", long, long + ";" + dir},
	} {
		got := pathWithout(tc.before, dir, expand)
		if tc.op == "add" {
			got = pathWith(tc.before, dir, expand)
		}
		if got != tc.after {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.after)
		}
	}
	// An entry that expands to the directory is the directory.
	if got := pathWith(`C:\Tools;%LP%`, dir, func(s string) string { return strings.ReplaceAll(s, "%LP%", dir) }); got != `C:\Tools;%LP%` {
		t.Fatalf("an entry expanding to the directory was added again: %q", got)
	}
}

// apply refuses a transaction that is not a begun install, and a release
// missing a staged file, before it changes anything.
func TestSystemApplyRefusesBeforeAnyChange(t *testing.T) {
	t.Run("not begun", func(t *testing.T) {
		h, dir := installedHost(t)
		writeJournal(t, dir, phaseApplying)
		if err := runSystemSteps(context.Background(), h, "v2", []string{"apply", dir, testTxn}); !errors.Is(err, errInstallerStepInvalid) {
			t.Fatalf("apply of an applying transaction = %v", err)
		}
		if h.restores != 0 || h.key == nil || string(h.key) != `"1.0.0"` {
			t.Fatalf("apply changed state: restores %d, key %s", h.restores, h.key)
		}
	})
	t.Run("staged directory", func(t *testing.T) {
		h, dir := installedHost(t)
		stageRelease(t, h, dir, "v2")
		// A directory where a staged file belongs would move into place.
		notice := filepath.Join(dir, txnRoot, testTxn, "staging", "NOTICE")
		if err := os.Remove(notice); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(notice, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := runSystemSteps(context.Background(), h, "v2", []string{"apply", dir, testTxn}); !errors.Is(err, errInstallNotCommitted) {
			t.Fatalf("apply = %v", err)
		}
		if got := readProduct(t, dir); !slices.Equal(got, allOf(len(productFiles), "v1")) || len(h.running) != 2 || string(h.key) != `"1.0.0"` {
			t.Fatalf("after a refused apply: files %v, running %v, key %s", got, h.running, h.key)
		}
		assertNoTransaction(t, dir)
	})
}

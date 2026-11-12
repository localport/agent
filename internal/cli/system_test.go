package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/localport/agent/internal/service"
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
	// marked is the open-transaction list.
	marked []string

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
func (f *fakeInstallHost) checkInstallDir(string) error   { return f.dirErr }
func (f *fakeInstallHost) lockServiceConfig(context.Context) (func(), error) {
	if f.lockErr != nil {
		return nil, f.lockErr
	}
	f.locks++
	return func() {}, nil
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
func (f *fakeInstallHost) restoreServices(_ context.Context, raw json.RawMessage) ([]string, error) {
	f.restores++
	if err := f.failing("restore"); err != nil {
		return nil, err
	}
	f.running = nil
	if f.fail["unsafeprogram"] {
		// The recorded program fails the binary rule: deleted, not restored.
		f.definition, f.existed = "", false
		return []string{"localport-device", "localport-session"}, nil
	}
	return nil, json.Unmarshal(raw, &f.definition)
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
func (f *fakeInstallHost) markOpen(dir string) error {
	if err := f.failing("mark"); err != nil {
		return err
	}
	f.marked = mergeNames(f.marked, []string{dir})
	return nil
}
func (f *fakeInstallHost) markClosed(dir string) error {
	f.marked = slices.DeleteFunc(f.marked, func(d string) bool { return d == dir })
	return nil
}

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
	err := runSystemSteps(context.Background(), h, "v2.0.0", []string{"apply", dir, testTxn})
	if !errors.Is(err, errInstallMixed) || !errors.Is(err, errServicesNotRestored) {
		t.Fatalf("apply = %v, want errInstallMixed and the failed action's errServicesNotRestored", err)
	}
	// The machine is not back as it was, so the exit status is AG090's,
	// not the failed action's.
	var exitErr *service.ExitError
	if !errors.As(systemExitError(err), &exitErr) || exitErr.Code != 90 {
		t.Fatalf("exit status of a failed rollback = %v, want 90", exitErr)
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

// A journal is replayed only from a directory that passes the admin-only
// rule: every step refuses an unsafe directory before reading one.
func TestSystemStepsTrustNoJournalInAnUnsafeDirectory(t *testing.T) {
	for _, args := range [][]string{{"begin", "", "nsNext.tmp"}, {"rollback", ""}, {"uninstall", ""}, {"apply", "", testTxn}} {
		h, dir := installedHost(t)
		writeJournal(t, dir, phaseApplying)
		h.dirErr = errors.New("Users can add files")
		args[1] = dir
		if err := runSystemSteps(context.Background(), h, "v2", args); !errors.Is(err, errInstallDirUnsafe) {
			t.Errorf("%s = %v, want errInstallDirUnsafe", args[0], err)
		}
		if h.restores != 0 || len(h.running) != 0 && !slices.Equal(h.running, []string{"localport-session", "localport-device"}) {
			t.Errorf("%s replayed the journal: restores %d, running %v", args[0], h.restores, h.running)
		}
		if got := readProduct(t, dir); got[0] != "v2" {
			t.Errorf("%s moved files back from an untrusted journal", args[0])
		}
	}
}

// A journal naming a path outside the install directory is refused, not
// replayed.
func TestSystemRefusesAJournalWithAForeignPath(t *testing.T) {
	h, dir := installedHost(t)
	writeJournal(t, dir, phaseApplying)
	path := filepath.Join(dir, txnRoot, testTxn, journalFile)
	raw, _ := os.ReadFile(path)
	var j journal
	if err := json.Unmarshal(raw, &j); err != nil {
		t.Fatal(err)
	}
	j.Actions[1].To = filepath.Join(t.TempDir(), "elsewhere")
	raw, _ = json.Marshal(j)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runSystemSteps(context.Background(), h, "v2", []string{"rollback", dir}); !errors.Is(err, errInstallMixed) || h.restores != 0 {
		t.Fatalf("rollback = %v, restores %d; want a refusal before any replay", err, h.restores)
	}
}

// begin refuses a transaction id whose directory an earlier transaction
// left (recovery could not delete it), instead of mixing the two.
func TestSystemBeginRefusesALeftoverTransactionDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root deletes from a read-only directory")
	}
	h, dir := installedHost(t)
	stageRelease(t, h, dir, "v2")
	h.afterMovesHook(t, filepath.Join(dir, txnRoot, testTxn, "backup"))
	if err := runSystemSteps(context.Background(), h, "v2.0.0", []string{"apply", dir, testTxn}); err != nil {
		t.Fatal(err)
	}
	if err := runSystemSteps(context.Background(), h, "v3", []string{"begin", dir, testTxn}); !errors.Is(err, errInstallNotCommitted) {
		t.Fatalf("begin with the same id = %v, want errInstallNotCommitted", err)
	}
	if got := readProduct(t, dir); !slices.Equal(got, allOf(len(productFiles), "v2")) {
		t.Fatalf("product files = %v after the refused begin", got)
	}
}

// A file that cannot be deleted is moved aside under a leftover name in
// .localport-txn, freeing its transaction directory; the next recovery
// deletes the leftover once nothing holds it.
func TestSystemMovesAnUndeletableFileAside(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, txnRoot)
	held := filepath.Join(root, testTxn, "backup", "localport.exe")
	if err := os.MkdirAll(filepath.Dir(held), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(held, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	leftover, err := moveAside(root, held)
	if err != nil || !strings.HasPrefix(filepath.Base(leftover), leftoverPrefix) || filepath.Dir(leftover) != root || exists(held) {
		t.Fatalf("moveAside = %q, %v", leftover, err)
	}
	if err := recoverTransactions(context.Background(), &fakeInstallHost{}, dir); err != nil {
		t.Fatal(err)
	}
	if exists(leftover) {
		t.Fatal("recovery kept a leftover nothing holds")
	}
}

// A purge failing after the uninstall commits reports AG093; the uninstall
// stands.
func TestSystemUninstallPurgeFailureCarriesItsCode(t *testing.T) {
	h, dir := installedHost(t)
	h.fail["purge"] = true
	if err := runSystemSteps(context.Background(), h, "v1", []string{"uninstall", dir, "--purge"}); !errors.Is(err, errPurgeFailed) {
		t.Fatalf("uninstall --purge = %v, want errPurgeFailed", err)
	}
	if h.deleted != 1 || exists(filepath.Join(dir, "localport.exe")) {
		t.Fatalf("the uninstall did not stand: deleted %d", h.deleted)
	}
}

// A step's exit status is its code's number; an error without a code
// exits 1.
func TestSystemExitStatusIsTheCodeNumber(t *testing.T) {
	var exitErr *service.ExitError
	if err := systemExitError(fmt.Errorf("%w: held", errServiceConfigBusy)); !errors.As(err, &exitErr) || exitErr.Code != 91 || !errors.Is(err, errServiceConfigBusy) {
		t.Fatalf("AG091 = %v", err)
	}
	plain := errors.New("plain")
	if err := systemExitError(plain); err != plain {
		t.Fatalf("an uncoded error = %v, want it unchanged", err)
	}
	if systemExitError(nil) != nil {
		t.Fatal("nil became an error")
	}
}

// Only a transaction in phase applying counts as open: its rollback would
// rewrite the service definitions.
func TestOpenInstallTransaction(t *testing.T) {
	for phase, want := range map[string]string{phaseApplying: testTxn, phaseBegun: "", phaseCommitted: ""} {
		_, dir := installedHost(t)
		writeJournal(t, dir, phase)
		if got := openInstallTransaction(dir); got != want {
			t.Errorf("phase %s: open = %q, want %q", phase, got, want)
		}
	}
	if got := openInstallTransaction(t.TempDir()); got != "" {
		t.Errorf("no transaction directory: open = %q", got)
	}
}

// A rollback whose recorded service program fails the binary rule deletes
// those services instead of restoring them, finishes, starts none of them,
// and still reports AG090: nothing is left to retry, but the machine is not
// as it was.
func TestSystemRollbackRemovesAServiceWithAnUnsafeProgram(t *testing.T) {
	h, dir := installedHost(t)
	stageRelease(t, h, dir, "v2")
	h.fail["install"], h.fail["unsafeprogram"] = true, true
	err := runSystemSteps(context.Background(), h, "v2.0.0", []string{"apply", dir, testTxn})
	var exitErr *service.ExitError
	if !errors.Is(err, errInstallMixed) || !errors.As(systemExitError(err), &exitErr) || exitErr.Code != 90 {
		t.Fatalf("apply = %v, want AG090 (exit 90)", err)
	}
	if !strings.Contains(err.Error(), "localport service install") {
		t.Fatalf("apply = %v, want the remedy named", err)
	}
	if h.existed || len(h.running) != 0 {
		t.Fatalf("services after rollback: existed %v, running %v; want removed and none started", h.existed, h.running)
	}
	if got := readProduct(t, dir); !slices.Equal(got, allOf(len(productFiles), "v1")) {
		t.Fatalf("files after rollback = %v", got)
	}
	assertNoTransaction(t, dir)
}

// The open-transaction record names the directory from before the first
// change until the transaction commits or is rolled back, and stays while a
// failed rollback leaves the transaction open.
func TestSystemOpenTransactionRecord(t *testing.T) {
	t.Run("commit", func(t *testing.T) {
		h, dir := installedHost(t)
		stageRelease(t, h, dir, "v2")
		var during []string
		h.onKeyWrite = func() { during = slices.Clone(h.marked) }
		if err := runSystemSteps(context.Background(), h, "v2.0.0", []string{"apply", dir, testTxn}); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(during, []string{dir}) || len(h.marked) != 0 {
			t.Fatalf("record during apply %v, after %v; want [%s] then empty", during, h.marked, dir)
		}
	})
	t.Run("record refused", func(t *testing.T) {
		h, dir := installedHost(t)
		stageRelease(t, h, dir, "v2")
		h.fail["mark"] = true
		if err := runSystemSteps(context.Background(), h, "v2.0.0", []string{"apply", dir, testTxn}); !errors.Is(err, errInstallNotCommitted) {
			t.Fatalf("apply = %v, want errInstallNotCommitted", err)
		}
		if !slices.Equal(h.running, []string{"localport-session", "localport-device"}) || readProduct(t, dir)[0] != "v1" {
			t.Fatal("apply changed the machine without a record")
		}
	})
	t.Run("rollback", func(t *testing.T) {
		h, dir := installedHost(t)
		stageRelease(t, h, dir, "v2")
		h.fail["path"] = true
		h.path = `C:\Windows`
		if err := runSystemSteps(context.Background(), h, "v2.0.0", []string{"apply", dir, testTxn}); !errors.Is(err, errMachinePathNotSet) {
			t.Fatalf("apply = %v", err)
		}
		if len(h.marked) != 0 {
			t.Fatalf("record after a rollback = %v", h.marked)
		}
	})
	t.Run("failed rollback keeps it", func(t *testing.T) {
		h, dir := installedHost(t)
		stageRelease(t, h, dir, "v2")
		h.fail["install"], h.fail["restore"] = true, true
		if err := runSystemSteps(context.Background(), h, "v2.0.0", []string{"apply", dir, testTxn}); !errors.Is(err, errInstallMixed) {
			t.Fatalf("apply = %v", err)
		}
		if !slices.Equal(h.marked, []string{dir}) {
			t.Fatalf("record with the transaction still open = %v", h.marked)
		}
		h.fail["restore"] = false
		if err := runSystemSteps(context.Background(), h, "v2.0.0", []string{"rollback", dir}); err != nil || len(h.marked) != 0 {
			t.Fatalf("retried rollback = %v, record %v", err, h.marked)
		}
	})
	t.Run("uninstall", func(t *testing.T) {
		h, dir := installedHost(t)
		if err := runSystemSteps(context.Background(), h, "v1", []string{"uninstall", dir}); err != nil || len(h.marked) != 0 {
			t.Fatalf("uninstall = %v, record %v", err, h.marked)
		}
	})
}

// The record keeps a directory while another transaction in it is still
// open.
func TestSystemRecordKeepsADirectoryWithAnotherOpenTransaction(t *testing.T) {
	h, dir := installedHost(t)
	writeJournal(t, dir, phaseApplying)
	h.marked = []string{dir}
	(&transaction{host: h, dir: dir}).closeMarker()
	if !slices.Equal(h.marked, []string{dir}) {
		t.Fatalf("record = %v, want the directory kept", h.marked)
	}
}

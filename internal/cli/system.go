package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/localport/agent/internal/errcode"
)

// `localport system <step>` is the Windows installer's internal command: the
// NSIS installer and uninstaller run each step from a copy of the new
// localport.exe and check its exit status. It is hidden from `localport
// help`, refuses unless elevated, and is built on Windows only
// (system_windows.go); the transaction logic here is platform-neutral so it
// is tested on every platform.
//
// An install or uninstall is one transaction, after Windows Installer's
// model: a journal records each change before it is made, any failure undoes
// every recorded change in reverse, an interrupted transaction is undone by
// the next installer or uninstaller run, and backups of replaced files are
// kept until the transaction commits (docs/agents/agent/cli.md "Windows
// installer steps").

var (
	errInstallerNotElevated = errcode.New(errcode.InstallerNotElevated)
	errInstallDirUnsafe     = errcode.New(errcode.InstallDirUnsafe)
	errServicesNotStopped   = errcode.New(errcode.ServicesNotStopped)
	errInstallNotCommitted  = errcode.New(errcode.InstallNotCommitted)
	errServicesNotRestored  = errcode.New(errcode.ServicesNotRestored)
	errForeignServiceInDir  = errcode.New(errcode.ForeignServiceInDir)
	errMachinePathNotSet    = errcode.New(errcode.MachinePathNotSet)
	errInstallerStepInvalid = errcode.New(errcode.InstallerStepInvalid)
	errUninstallNotPrepared = errcode.New(errcode.UninstallNotPrepared)
	errInstallMixed         = errcode.New(errcode.InstallMixed)
	errServiceConfigBusy    = errcode.New(errcode.ServiceConfigBusy)
	errUninstallEntryNotSet = errcode.New(errcode.UninstallEntryNotSet)
)

// productFiles are the files the installer puts in the install directory,
// replaced together so every one comes from one release.
var productFiles = []string{"localport.exe", "localport-session.exe", "uninstall.exe", "LICENSE", "NOTICE", "THIRD_PARTY_NOTICES"}

const (
	// txnRoot holds one directory per transaction inside the install
	// directory: staging\, backup\ and journal.json.
	txnRoot     = ".localport-txn"
	journalFile = "journal.json"

	opInstall   = "install"
	opUninstall = "uninstall"

	phaseBegun     = "begun"
	phaseApplying  = "applying"
	phaseCommitted = "committed"

	actStop     = "stop"
	actMove     = "move"
	actKey      = "key"
	actPath     = "path"
	actServices = "services"
)

// txnName is the installer's transaction id, the base name of NSIS's
// $PLUGINSDIR, or the uninstaller's own random id.
var txnName = regexp.MustCompile(`^(ns[0-9A-Za-z]+\.tmp|u[0-9a-f]{16})$`)

// installHost is what the transaction needs from the machine.
type installHost interface {
	elevated() bool
	// prepareInstallDir creates dir admin-only when it is missing, then
	// refuses it unless it passes the device service binary rule.
	prepareInstallDir(dir string) error
	// lockServiceConfig takes the lock every writer of the service
	// definitions holds; abandoned means its last holder died holding it.
	lockServiceConfig(ctx context.Context) (unlock func(), abandoned bool, err error)
	// snapshotServices records the owned services' definitions and state:
	// running lists those running, existed whether any exists.
	snapshotServices() (snap json.RawMessage, running []string, existed bool, err error)
	stopServices(ctx context.Context) ([]string, error)
	startServices(ctx context.Context, names []string) error
	// restoreServices writes snap's definitions back and leaves the owned
	// services stopped.
	restoreServices(ctx context.Context, snap json.RawMessage) error
	// installServices registers and starts the owned services for exe.
	installServices(ctx context.Context, exe string) error
	deleteServices(ctx context.Context) error
	purge(ctx context.Context) error
	// foreignServicesIn lists services not created by localport whose
	// program is inside dir.
	foreignServicesIn(dir string) ([]string, error)
	// readUninstallKey returns the Add/Remove Programs entry, nil when absent.
	readUninstallKey() (json.RawMessage, error)
	// restoreUninstallKey writes raw back exactly, or deletes the entry when
	// raw is nil.
	restoreUninstallKey(raw json.RawMessage) error
	writeUninstallKey(dir, version string, sizeKB uint32) error
	readPath() (value string, expandable bool, err error)
	writePath(value string, expandable bool) error
	expand(s string) string
	broadcastEnvironment() error
	// deleteAtReboot queues path for deletion when Windows next starts.
	deleteAtReboot(path string) error
	warn(msg string)
}

// runSystemSteps runs one installer step on host. version is the release the
// running binary belongs to.
func runSystemSteps(ctx context.Context, host installHost, version string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: name a step: begin, apply, rollback or uninstall", errInstallerStepInvalid)
	}
	if !host.elevated() {
		return fmt.Errorf("%w: system %s", errInstallerNotElevated, args[0])
	}
	step, rest := args[0], args[1:]
	purge := step == opUninstall && len(rest) == 2 && rest[1] == "--purge"
	if purge {
		rest = rest[:1]
	}
	want := 2
	if step == "rollback" || step == opUninstall {
		want = 1
	}
	if len(rest) != want || !filepath.IsAbs(rest[0]) || (want == 2 && !txnName.MatchString(rest[1])) {
		return fmt.Errorf("%w: system %s: want an absolute install directory%s", errInstallerStepInvalid, step, map[bool]string{true: " and a transaction id", false: ""}[want == 2])
	}
	dir := filepath.Clean(rest[0])
	switch step {
	case "begin":
		return beginInstall(ctx, host, dir, rest[1])
	case "apply":
		return applyInstall(ctx, host, dir, rest[1], version)
	case "rollback":
		return withServiceLock(ctx, host, dir, func() error { return nil })
	case opUninstall:
		return runUninstall(ctx, host, dir, purge)
	}
	return fmt.Errorf("%w: system: unknown step %q", errInstallerStepInvalid, step)
}

// withServiceLock runs fn holding the service configuration lock, after
// recovering every transaction an earlier run left open in dir.
func withServiceLock(ctx context.Context, host installHost, dir string, fn func() error) error {
	unlock, _, err := host.lockServiceConfig(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if err := recoverTransactions(ctx, host, dir); err != nil {
		return err
	}
	return fn()
}

// beginInstall recovers earlier transactions, readies the install directory
// and opens transaction txn at phase begun with its staging directory, into
// which NSIS then extracts the release.
func beginInstall(ctx context.Context, host installHost, dir, txn string) error {
	return withServiceLock(ctx, host, dir, func() error {
		if err := host.prepareInstallDir(dir); err != nil {
			return fmt.Errorf("%w: %s: %w", errInstallDirUnsafe, dir, err)
		}
		t := &transaction{host: host, dir: dir, j: journal{Op: opInstall, Txn: txn, Phase: phaseBegun}}
		for _, d := range []string{t.stagingDir(), t.backupDir()} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				return fmt.Errorf("%w: %w", errInstallNotCommitted, err)
			}
		}
		if err := t.save(); err != nil {
			return fmt.Errorf("%w: %w", errInstallNotCommitted, err)
		}
		return nil
	})
}

// applyInstall runs transaction txn: it stops the owned services, replaces
// every product file, writes the uninstall entry, adds dir to the machine
// Path and re-registers the services that existed, then commits and cleans
// up. Any failure rolls every change back.
func applyInstall(ctx context.Context, host installHost, dir, txn, version string) error {
	unlock, _, err := host.lockServiceConfig(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	t, err := loadTransaction(host, dir, txn)
	if err != nil {
		return fmt.Errorf("%w: %w", errInstallNotCommitted, err)
	}
	if t.j.Op != opInstall || t.j.Phase != phaseBegun {
		return fmt.Errorf("%w: transaction %s is %s %s, not a begun install", errInstallerStepInvalid, txn, t.j.Op, t.j.Phase)
	}
	for _, name := range productFiles {
		if fi, err := os.Lstat(filepath.Join(t.stagingDir(), name)); err != nil || !fi.Mode().IsRegular() {
			return t.fail(ctx, fmt.Errorf("%w: staged %s is missing or not a regular file: %v", errInstallNotCommitted, name, err))
		}
	}
	running, existed, err := t.snapshot()
	if err != nil {
		return t.fail(ctx, fmt.Errorf("%w: %w", errInstallNotCommitted, err))
	}
	if len(running) > 0 {
		if err := t.do(ctx, txnAction{Kind: actStop, Names: running}, errServicesNotStopped); err != nil {
			return err
		}
	}
	for _, name := range productFiles {
		current := filepath.Join(dir, name)
		if _, err := os.Lstat(current); err == nil {
			if err := t.do(ctx, txnAction{Kind: actMove, From: current, To: filepath.Join(t.backupDir(), name)}, errInstallNotCommitted); err != nil {
				return err
			}
		}
		if err := t.do(ctx, txnAction{Kind: actMove, From: filepath.Join(t.stagingDir(), name), To: current}, errInstallNotCommitted); err != nil {
			return err
		}
	}
	if err := t.do(ctx, txnAction{Kind: actKey, Version: strings.TrimPrefix(version, "v")}, errUninstallEntryNotSet); err != nil {
		return err
	}
	if err := t.editPath(ctx, "add", errMachinePathNotSet); err != nil {
		return err
	}
	if existed {
		if err := t.do(ctx, txnAction{Kind: actServices, To: filepath.Join(dir, "localport.exe")}, errServicesNotRestored); err != nil {
			return err
		}
	}
	if err := t.commit(); err != nil {
		return t.fail(ctx, err)
	}
	return nil
}

// runUninstall removes the owned services, the Path entry, the uninstall
// entry and every product file as one transaction, then, past its commit
// point, purges the device state when asked.
func runUninstall(ctx context.Context, host installHost, dir string, purge bool) error {
	return withServiceLock(ctx, host, dir, func() error {
		foreign, err := host.foreignServicesIn(dir)
		if err != nil {
			return fmt.Errorf("%w: %w", errUninstallNotPrepared, err)
		}
		if len(foreign) > 0 {
			return fmt.Errorf("%w: %s", errForeignServiceInDir, strings.Join(foreign, ", "))
		}
		id := make([]byte, 8)
		if _, err := rand.Read(id); err != nil {
			return fmt.Errorf("%w: %w", errUninstallNotPrepared, err)
		}
		t := &transaction{host: host, dir: dir, j: journal{Op: opUninstall, Txn: "u" + hex.EncodeToString(id), Phase: phaseBegun}}
		if err := os.MkdirAll(t.backupDir(), 0o755); err != nil {
			return fmt.Errorf("%w: %w", errUninstallNotPrepared, err)
		}
		running, existed, err := t.snapshot()
		if err != nil {
			return t.fail(ctx, fmt.Errorf("%w: %w", errUninstallNotPrepared, err))
		}
		if len(running) > 0 {
			if err := t.do(ctx, txnAction{Kind: actStop, Names: running}, errUninstallNotPrepared); err != nil {
				return err
			}
		}
		if existed {
			if err := t.do(ctx, txnAction{Kind: actServices}, errUninstallNotPrepared); err != nil {
				return err
			}
		}
		if err := t.editPath(ctx, "remove", errUninstallNotPrepared); err != nil {
			return err
		}
		if t.j.Key != nil {
			if err := t.do(ctx, txnAction{Kind: actKey}, errUninstallNotPrepared); err != nil {
				return err
			}
		}
		for _, name := range productFiles {
			current := filepath.Join(dir, name)
			if _, err := os.Lstat(current); err == nil {
				if err := t.do(ctx, txnAction{Kind: actMove, From: current, To: filepath.Join(t.backupDir(), name)}, errUninstallNotPrepared); err != nil {
					return err
				}
			}
		}
		if err := t.commit(); err != nil {
			return t.fail(ctx, err)
		}
		// Only when empty: anything else in them is not ours to remove.
		removeEmptyOrQueue(host, filepath.Join(dir, txnRoot))
		removeEmptyOrQueue(host, dir)
		if purge {
			// Irreversible, so after the commit point; the uninstall stands.
			return host.purge(ctx)
		}
		return nil
	})
}

// journal is a transaction's write-ahead record (journal.json).
type journal struct {
	Op    string `json:"op"`
	Txn   string `json:"txn"`
	Phase string `json:"phase"`
	// Services is the owned services' snapshot, Running those running.
	Services json.RawMessage `json:"services,omitempty"`
	Running  []string        `json:"running,omitempty"`
	// Key is the uninstall entry as found, KeyFound whether there was one.
	Key      json.RawMessage `json:"key,omitempty"`
	KeyFound bool            `json:"key_found"`
	Actions  []txnAction     `json:"actions"`
}

// txnAction is one recorded change, written before it is made (Done false)
// and again after (Done true). Rollback undoes every recorded action, done
// or not, by an inverse that tolerates the change not having happened.
type txnAction struct {
	Kind  string   `json:"kind"`
	Names []string `json:"names,omitempty"`
	// From and To are a move's paths; To is also the exe a services action
	// registers.
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
	// Edit (add, remove), Prior and Next are a Path change.
	Edit       string `json:"edit,omitempty"`
	Prior      string `json:"prior,omitempty"`
	Next       string `json:"next,omitempty"`
	Expandable bool   `json:"expandable,omitempty"`
	Version    string `json:"version,omitempty"`
	Done       bool   `json:"done"`
}

type transaction struct {
	host installHost
	dir  string
	j    journal
}

func (t *transaction) txnDir() string     { return filepath.Join(t.dir, txnRoot, t.j.Txn) }
func (t *transaction) stagingDir() string { return filepath.Join(t.txnDir(), "staging") }
func (t *transaction) backupDir() string  { return filepath.Join(t.txnDir(), "backup") }

func loadTransaction(host installHost, dir, txn string) (*transaction, error) {
	t := &transaction{host: host, dir: dir, j: journal{Txn: txn}}
	raw, err := os.ReadFile(filepath.Join(t.txnDir(), journalFile))
	if err != nil {
		return nil, fmt.Errorf("read the journal of transaction %s: %w", txn, err)
	}
	if err := json.Unmarshal(raw, &t.j); err != nil {
		return nil, fmt.Errorf("read the journal of transaction %s: %w", txn, err)
	}
	if t.j.Txn != txn {
		return nil, fmt.Errorf("the journal of transaction %s names %q", txn, t.j.Txn)
	}
	return t, nil
}

// save writes the journal atomically: a synced temporary file renamed over
// the journal, so a crash leaves the old record or the new one.
func (t *transaction) save() error {
	raw, err := json.Marshal(t.j)
	if err != nil {
		return err
	}
	path := filepath.Join(t.txnDir(), journalFile)
	f, err := os.OpenFile(path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("write the install journal: %w", err)
	}
	if _, err := f.Write(raw); err != nil {
		return errors.Join(fmt.Errorf("write the install journal: %w", err), f.Close())
	}
	if err := f.Sync(); err != nil {
		return errors.Join(fmt.Errorf("write the install journal: %w", err), f.Close())
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write the install journal: %w", err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return fmt.Errorf("write the install journal: %w", err)
	}
	return nil
}

// snapshot records the services and the uninstall entry, then moves the
// transaction to phase applying.
func (t *transaction) snapshot() (running []string, existed bool, err error) {
	snap, running, existed, err := t.host.snapshotServices()
	if err != nil {
		return nil, false, err
	}
	key, err := t.host.readUninstallKey()
	if err != nil {
		return nil, false, err
	}
	t.j.Services, t.j.Running, t.j.Key, t.j.KeyFound = snap, running, key, key != nil
	t.j.Phase = phaseApplying
	return running, existed, t.save()
}

// do records a, makes the change, and records it done. A failure rolls the
// transaction back and returns the change's error under code.
func (t *transaction) do(ctx context.Context, a txnAction, code error) error {
	t.j.Actions = append(t.j.Actions, a)
	if err := t.save(); err != nil {
		return t.fail(ctx, fmt.Errorf("%w: %w", code, err))
	}
	last := &t.j.Actions[len(t.j.Actions)-1]
	if err := t.apply(ctx, last); err != nil {
		return t.fail(ctx, fmt.Errorf("%w: %w", code, err))
	}
	last.Done = true
	if err := t.save(); err != nil {
		return t.fail(ctx, fmt.Errorf("%w: %w", code, err))
	}
	return nil
}

func (t *transaction) apply(ctx context.Context, a *txnAction) error {
	switch a.Kind {
	case actStop:
		stopped, err := t.host.stopServices(ctx)
		// Every name stays in the record: the inverse starts each one that
		// was running, whichever this stop reached.
		a.Names = mergeNames(a.Names, stopped)
		return err
	case actMove:
		if err := os.Rename(a.From, a.To); err != nil {
			return fmt.Errorf("move %s to %s: %w", a.From, a.To, err)
		}
		return nil
	case actKey:
		if t.j.Op == opUninstall {
			return t.host.restoreUninstallKey(nil)
		}
		return t.host.writeUninstallKey(t.dir, a.Version, installedSizeKB(t.dir))
	case actPath:
		return t.host.writePath(a.Next, a.Expandable)
	case actServices:
		if t.j.Op == opUninstall {
			return t.host.deleteServices(ctx)
		}
		return t.host.installServices(ctx, a.To)
	}
	return fmt.Errorf("unknown action %q", a.Kind)
}

// editPath records and makes the machine Path change edit (add or remove
// t.dir), when the value changes.
func (t *transaction) editPath(ctx context.Context, edit string, code error) error {
	if edit == "add" {
		if fi, err := os.Stat(t.dir); err != nil || !fi.IsDir() {
			return t.fail(ctx, fmt.Errorf("%w: %s is not an existing directory", code, t.dir))
		}
	}
	prior, expandable, err := t.host.readPath()
	if err != nil {
		return t.fail(ctx, fmt.Errorf("%w: %w", code, err))
	}
	next := pathWithout(prior, t.dir, t.host.expand)
	if edit == "add" {
		next = pathWith(prior, t.dir, t.host.expand)
	}
	if next == prior {
		return nil
	}
	return t.do(ctx, txnAction{Kind: actPath, Edit: edit, Prior: prior, Next: next, Expandable: expandable}, code)
}

// fail rolls the transaction back and returns cause, joined with the
// rollback's own failure under errInstallMixed when undoing failed too.
func (t *transaction) fail(ctx context.Context, cause error) error {
	if err := t.rollback(ctx); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

// rollback undoes every recorded action in reverse, then removes the
// transaction directory. When an inverse fails the journal stays, so the
// next run retries, and errInstallMixed is returned.
func (t *transaction) rollback(ctx context.Context) error {
	var errs []error
	for i := len(t.j.Actions) - 1; i >= 0; i-- {
		if err := t.undo(ctx, t.j.Actions[i]); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%w: transaction %s: %w", errInstallMixed, t.j.Txn, err)
	}
	removeOrQueue(t.host, t.txnDir())
	return nil
}

func (t *transaction) undo(ctx context.Context, a txnAction) error {
	switch a.Kind {
	case actStop:
		return t.host.startServices(ctx, a.Names)
	case actMove:
		if !exists(a.To) || exists(a.From) {
			return nil
		}
		if err := os.Rename(a.To, a.From); err != nil {
			return fmt.Errorf("move %s back to %s: %w", a.To, a.From, err)
		}
		return nil
	case actKey:
		var prior json.RawMessage
		if t.j.KeyFound {
			prior = t.j.Key
		}
		return t.host.restoreUninstallKey(prior)
	case actPath:
		current, expandable, err := t.host.readPath()
		if err != nil {
			return err
		}
		if current == a.Next {
			return t.host.writePath(a.Prior, a.Expandable)
		}
		// Another program changed Path meanwhile: undo only this entry.
		restored := pathWith(current, t.dir, t.host.expand)
		if a.Edit == "add" {
			restored = pathWithout(current, t.dir, t.host.expand)
		}
		if restored == current {
			return nil
		}
		return t.host.writePath(restored, expandable)
	case actServices:
		return t.host.restoreServices(ctx, t.j.Services)
	}
	return fmt.Errorf("unknown action %q", a.Kind)
}

// commit marks the transaction committed, then finishes it. An error means
// it is not committed, and the caller rolls back.
func (t *transaction) commit() error {
	t.j.Phase = phaseCommitted
	if err := t.save(); err != nil {
		// Not committed: the caller's error path rolls back.
		return fmt.Errorf("%w: %w", errInstallNotCommitted, err)
	}
	t.finish()
	return nil
}

// finish removes the transaction directory (backups still in use are
// deleted at reboot) and announces a Path change. Nothing here undoes the
// transaction, so failures only warn.
func (t *transaction) finish() {
	removeOrQueue(t.host, t.txnDir())
	for _, a := range t.j.Actions {
		if a.Kind == actPath && a.Done {
			if err := t.host.broadcastEnvironment(); err != nil {
				t.host.warn(fmt.Sprintf("the Path change is saved, but running programs were not told: %v", err))
			}
			return
		}
	}
}

// recoverTransactions resolves every transaction directory an earlier run
// left in dir: a committed one is finished, one in phase applying is rolled
// back, and one begun (nothing changed yet) or without a journal is removed.
// The caller holds the service configuration lock.
func recoverTransactions(ctx context.Context, host installHost, dir string) error {
	entries, err := os.ReadDir(filepath.Join(dir, txnRoot))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %w", errInstallMixed, err)
	}
	for _, e := range entries {
		if !e.IsDir() || !txnName.MatchString(e.Name()) {
			continue
		}
		t, err := loadTransaction(host, dir, e.Name())
		switch {
		case errors.Is(err, fs.ErrNotExist):
			removeOrQueue(host, filepath.Join(dir, txnRoot, e.Name()))
			continue
		case err != nil:
			return fmt.Errorf("%w: %w; fix or remove %s, then run the installer again", errInstallMixed, err, filepath.Join(dir, txnRoot, e.Name()))
		}
		switch t.j.Phase {
		case phaseCommitted:
			t.finish()
		case phaseApplying:
			host.warn(fmt.Sprintf("rolling back interrupted %s transaction %s", t.j.Op, t.j.Txn))
			if err := t.rollback(ctx); err != nil {
				return err
			}
		default:
			removeOrQueue(host, t.txnDir())
		}
	}
	return nil
}

// removeOrQueue removes path and everything under it; an entry Windows
// refuses to delete (an image still running) is queued for deletion at
// reboot, after the entries inside it. Failures only warn.
func removeOrQueue(host installHost, path string) {
	var paths []string
	_ = filepath.WalkDir(path, func(p string, _ fs.DirEntry, err error) error {
		if err == nil {
			paths = append(paths, p)
		}
		return nil
	})
	for i := len(paths) - 1; i >= 0; i-- {
		if err := os.Remove(paths[i]); err == nil || errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err := host.deleteAtReboot(paths[i]); err != nil {
			host.warn(fmt.Sprintf("%s was not deleted and could not be queued for deletion at reboot: %v", paths[i], err))
		}
	}
}

// removeEmptyOrQueue removes the directory path when it is empty, and
// otherwise queues it for deletion at reboot, which succeeds only if the
// entries queued before it leave it empty.
func removeEmptyOrQueue(host installHost, path string) {
	if err := os.Remove(path); err == nil || errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err := host.deleteAtReboot(path); err != nil {
		host.warn(fmt.Sprintf("%s was not removed: %v", path, err))
	}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func mergeNames(a, b []string) []string {
	out := slices.Clone(a)
	for _, n := range b {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// installedSizeKB is the size of the product files in dir, for the
// uninstall entry's EstimatedSize.
func installedSizeKB(dir string) uint32 {
	var total int64
	for _, name := range productFiles {
		if fi, err := os.Stat(filepath.Join(dir, name)); err == nil {
			total += fi.Size()
		}
	}
	return uint32((total + 1023) / 1024)
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

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
	"strconv"
	"strings"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/service"
)

// `localport system <step>` is the Windows installer's internal command: the
// NSIS installer and uninstaller run each step from a copy of the new
// localport.exe and check its exit status. It is hidden from `localport
// help`, refuses unless elevated, and is built on Windows only
// (system_windows.go); the transaction logic here is platform-neutral so it
// is tested on every platform.
//
// An install or uninstall is one transaction, after Windows Installer's model:
// a journal records each change before it is made, any failure undoes every
// recorded change in reverse, an interrupted transaction is undone by the next
// installer or uninstaller run, and backups of replaced files are kept until
// the transaction commits.

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
	errPurgeFailed          = errcode.New(errcode.PurgeFailed)
)

// productFiles are the files the installer puts in the install directory,
// replaced together so every one comes from one release.
var productFiles = []string{"localport.exe", "localport-session.exe", uninstallerFile, "LICENSE", "NOTICE", "THIRD_PARTY_NOTICES"}

// uninstallerFile is the NSIS uninstaller, the process that runs
// `system uninstall`. Under `_?=` it runs from this file and holds it open,
// so the uninstall transaction leaves it and the install directory to the
// uninstaller, which deletes both once this step succeeds.
const uninstallerFile = "uninstall.exe"

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
	// checkInstallDir refuses an existing dir that does not pass the device
	// service binary rule, without changing it.
	checkInstallDir(dir string) error
	// lockServiceConfig takes the lock every writer of the service
	// definitions holds; every failure carries AG091.
	lockServiceConfig(ctx context.Context) (unlock func(), err error)
	// snapshotServices records the owned services' definitions and state:
	// running lists those running, existed whether any exists.
	snapshotServices() (snap json.RawMessage, running []string, existed bool, err error)
	stopServices(ctx context.Context) ([]string, error)
	startServices(ctx context.Context, names []string) error
	// restoreServices writes snap's definitions back and leaves the owned
	// services stopped. A service whose recorded program will fail the
	// device service binary rule once the rollback is done is deleted
	// instead and listed in removed; programAt maps a program path to the
	// file that will be there, "" when none will be.
	restoreServices(ctx context.Context, snap json.RawMessage, programAt func(string) string) (removed []string, err error)
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
	// markOpen and markClosed add and remove dir in the machine's list of
	// directories with an open transaction (after Windows Installer's
	// InProgress key), which up, the service commands and the other
	// steps check; listOpen reads it.
	markOpen(dir string) error
	markClosed(dir string) error
	listOpen() ([]string, error)
	warn(msg string)
}

// runSystemSteps runs one installer step on host. version is the release the
// running binary belongs to.
func runSystemSteps(ctx context.Context, host installHost, version string, args []string) error {
	if len(args) == 0 {
		return errInstallerStepInvalid.With(nil, "name a step: begin, apply, rollback or uninstall")
	}
	if !host.elevated() {
		return errInstallerNotElevated.With(nil, fmt.Sprintf("system %s", args[0]))
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
		return errInstallerStepInvalid.With(nil, fmt.Sprintf("system %s: want an absolute install directory%s", step, map[bool]string{true: " and a transaction id", false: ""}[want == 2]))
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
	return errInstallerStepInvalid.With(nil, fmt.Sprintf("system: unknown step %q", step))
}

// systemExitError gives err the exit status of its installer code, the
// code's number (AG083 exits 83), so the installer, install.ps1 and winget
// can tell failures apart; an error without one exits 1.
func systemExitError(err error) error {
	var coded *errcode.Error
	if err == nil || !errors.As(err, &coded) {
		return err
	}
	n, convErr := strconv.Atoi(strings.TrimPrefix(string(coded.Code), "AG"))
	if convErr != nil || n <= 0 || n > 255 {
		return err
	}
	return &service.ExitError{Code: n, Err: err}
}

// withServiceLock runs fn holding the service configuration lock, after
// recovering every transaction an earlier run left open in dir. A journal is
// read only from a directory that passes the admin-only rule, since its
// replay registers and starts services.
func withServiceLock(ctx context.Context, host installHost, dir string, fn func() error) error {
	unlock, err := host.lockServiceConfig(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if exists(dir) {
		if err := host.checkInstallDir(dir); err != nil {
			return errInstallDirUnsafe.With(err, dir)
		}
		if err := recoverTransactions(ctx, host, dir); err != nil {
			return err
		}
	} else {
		// Nothing can be open in a directory that is gone.
		(&transaction{host: host, dir: dir}).closeMarker()
	}
	return fn()
}

// beginInstall recovers earlier transactions, readies the install directory
// and opens transaction txn at phase begun with its staging directory, into
// which NSIS then extracts the release.
func beginInstall(ctx context.Context, host installHost, dir, txn string) error {
	return withServiceLock(ctx, host, dir, func() error {
		if err := host.prepareInstallDir(dir); err != nil {
			return errInstallDirUnsafe.With(err, dir)
		}
		t := &transaction{host: host, dir: dir, j: journal{Op: opInstall, Txn: txn, Phase: phaseBegun}}
		// Recovery removed every earlier transaction directory it could; one
		// left under this id holds files of an earlier transaction.
		if exists(t.txnDir()) {
			return errInstallNotCommitted.With(nil, fmt.Sprintf("%s is left from an earlier transaction; restart Windows, then run the installer again", t.txnDir()))
		}
		for _, d := range []string{t.stagingDir(), t.backupDir()} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				return errInstallNotCommitted.With(err, "")
			}
		}
		if err := t.save(); err != nil {
			return errInstallNotCommitted.With(err, "")
		}
		return nil
	})
}

// applyInstall runs transaction txn: it stops the owned services, replaces
// every product file, writes the uninstall entry, adds dir to the machine
// Path and re-registers the services that existed, then commits and cleans
// up. Any failure rolls every change back.
func applyInstall(ctx context.Context, host installHost, dir, txn, version string) error {
	unlock, err := host.lockServiceConfig(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if err := host.checkInstallDir(dir); err != nil {
		return errInstallDirUnsafe.With(err, dir)
	}
	t, err := loadTransaction(host, dir, txn)
	if err != nil {
		return errInstallNotCommitted.With(err, "")
	}
	if t.j.Op != opInstall || t.j.Phase != phaseBegun {
		return errInstallerStepInvalid.With(nil, fmt.Sprintf("transaction %s is %s %s, not a begun install", txn, t.j.Op, t.j.Phase))
	}
	if err := refuseOtherOpenTransaction(host, dir); err != nil {
		return err
	}
	for _, name := range productFiles {
		if fi, err := os.Lstat(filepath.Join(t.stagingDir(), name)); err != nil || !fi.Mode().IsRegular() {
			return t.fail(ctx, errInstallNotCommitted.With(err, fmt.Sprintf("staged %s is missing or not a regular file", name)))
		}
	}
	running, existed, err := t.snapshot()
	if err != nil {
		return t.fail(ctx, errInstallNotCommitted.With(err, ""))
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
// entry and every product file but the running uninstaller as one
// transaction, then, past its commit point, purges the device state when
// asked. The uninstaller deletes itself and dir after this step, also when
// only the purge failed (AG093).
func runUninstall(ctx context.Context, host installHost, dir string, purge bool) error {
	return withServiceLock(ctx, host, dir, func() error {
		if err := refuseOtherOpenTransaction(host, dir); err != nil {
			return err
		}
		foreign, err := host.foreignServicesIn(dir)
		if err != nil {
			return errUninstallNotPrepared.With(err, "")
		}
		if len(foreign) > 0 {
			return errForeignServiceInDir.With(nil, strings.Join(foreign, ", "))
		}
		id := make([]byte, 8)
		if _, err := rand.Read(id); err != nil {
			return errUninstallNotPrepared.With(err, "")
		}
		t := &transaction{host: host, dir: dir, j: journal{Op: opUninstall, Txn: "u" + hex.EncodeToString(id), Phase: phaseBegun}}
		if err := os.MkdirAll(t.backupDir(), 0o755); err != nil {
			return errUninstallNotPrepared.With(err, "")
		}
		running, existed, err := t.snapshot()
		if err != nil {
			return t.fail(ctx, errUninstallNotPrepared.With(err, ""))
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
			if name == uninstallerFile {
				continue
			}
			if _, err := os.Lstat(current); err == nil {
				if err := t.do(ctx, txnAction{Kind: actMove, From: current, To: filepath.Join(t.backupDir(), name)}, errUninstallNotPrepared); err != nil {
					return err
				}
			}
		}
		if err := t.commit(); err != nil {
			return t.fail(ctx, err)
		}
		// Only when empty: anything else in it is not ours to remove. dir
		// itself goes with the uninstaller (uninstallerFile).
		removeEmptyOrQueue(host, filepath.Join(dir, txnRoot))
		if purge {
			// Irreversible, so after the commit point; the uninstall stands.
			if err := host.purge(ctx); err != nil {
				return errPurgeFailed.With(err, "")
			}
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
	// removed lists the services a rollback deleted instead of restoring.
	removed []string
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
	if err := t.checkPaths(); err != nil {
		return nil, fmt.Errorf("the journal of transaction %s: %w", txn, err)
	}
	return t, nil
}

// checkPaths refuses a journal whose actions name a path outside the
// install directory, or a services action for another executable.
func (t *transaction) checkPaths() error {
	inside := func(p string) bool {
		rel, err := filepath.Rel(t.dir, p)
		return err == nil && filepath.IsAbs(p) && rel != "." && !strings.HasPrefix(rel, "..")
	}
	for _, a := range t.j.Actions {
		switch a.Kind {
		case actMove:
			if !inside(a.From) || !inside(a.To) {
				return fmt.Errorf("a move names %s and %s, not paths inside %s", a.From, a.To, t.dir)
			}
		case actServices:
			if a.To != "" && a.To != filepath.Join(t.dir, "localport.exe") {
				return fmt.Errorf("a services action names %s", a.To)
			}
		}
	}
	return nil
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
	// Before the first change, so no change exists that the list misses.
	if err := t.host.markOpen(t.dir); err != nil {
		return nil, false, fmt.Errorf("record the open transaction: %w", err)
	}
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
func (t *transaction) do(ctx context.Context, a txnAction, code *errcode.Error) error {
	t.j.Actions = append(t.j.Actions, a)
	if err := t.save(); err != nil {
		return t.fail(ctx, code.With(err, ""))
	}
	last := &t.j.Actions[len(t.j.Actions)-1]
	if err := t.apply(ctx, last); err != nil {
		return t.fail(ctx, code.With(err, ""))
	}
	last.Done = true
	if err := t.save(); err != nil {
		return t.fail(ctx, code.With(err, ""))
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
func (t *transaction) editPath(ctx context.Context, edit string, code *errcode.Error) error {
	if edit == "add" {
		if fi, err := os.Stat(t.dir); err != nil || !fi.IsDir() {
			return t.fail(ctx, code.With(nil, t.dir+" is not an existing directory"))
		}
	}
	prior, expandable, err := t.host.readPath()
	if err != nil {
		return t.fail(ctx, code.With(err, ""))
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
		// The rollback's AG090 first: its code is the step's exit status,
		// since the machine is not back as it was.
		return errors.Join(err, cause)
	}
	return cause
}

// rollback undoes every recorded action in reverse, then removes the
// transaction directory. When an inverse fails the journal stays, so the
// next run retries, and errInstallMixed is returned. A service deleted
// instead of restored also returns errInstallMixed, after the transaction
// is removed: nothing is left to retry, but the machine is not as it was.
func (t *transaction) rollback(ctx context.Context) error {
	var errs []error
	for i := len(t.j.Actions) - 1; i >= 0; i-- {
		if err := t.undo(ctx, t.j.Actions[i]); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return errInstallMixed.With(err, fmt.Sprintf("transaction %s", t.j.Txn))
	}
	removeOrQueue(t.host, t.txnDir())
	t.closeMarker()
	if len(t.removed) > 0 {
		return errInstallMixed.With(nil, fmt.Sprintf("transaction %s was undone, but services %s were removed instead of restored because the program they ran fails the device service binary rule; run `localport service install` as an Administrator", t.j.Txn, strings.Join(t.removed, ", ")))
	}
	return nil
}

func (t *transaction) undo(ctx context.Context, a txnAction) error {
	switch a.Kind {
	case actStop:
		var names []string
		for _, n := range a.Names {
			if !slices.Contains(t.removed, n) {
				names = append(names, n)
			}
		}
		return t.host.startServices(ctx, names)
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
		removed, err := t.host.restoreServices(ctx, t.j.Services, t.programAfterRollback)
		t.removed = mergeNames(t.removed, removed)
		return err
	}
	return fmt.Errorf("unknown action %q", a.Kind)
}

// commit marks the transaction committed, then finishes it. An error means
// it is not committed, and the caller rolls back.
func (t *transaction) commit() error {
	t.j.Phase = phaseCommitted
	if err := t.save(); err != nil {
		// Not committed: the caller's error path rolls back.
		return errInstallNotCommitted.With(err, "")
	}
	t.finish()
	return nil
}

// finish removes the transaction directory (backups still in use are
// deleted at reboot) and announces a Path change. Nothing here undoes the
// transaction, so failures only warn.
func (t *transaction) finish() {
	removeOrQueue(t.host, t.txnDir())
	t.closeMarker()
	for _, a := range t.j.Actions {
		if a.Kind == actPath && a.Done {
			if err := t.host.broadcastEnvironment(); err != nil {
				t.host.warn(fmt.Sprintf("the Path change is saved, but running programs were not told: %s", userText(err)))
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
		(&transaction{host: host, dir: dir}).closeMarker()
		return nil
	}
	if err != nil {
		return errInstallMixed.With(err, "")
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), leftoverPrefix) {
			// Deleted once the program that held it has exited; one still
			// in use stays queued for deletion at reboot.
			_ = os.Remove(filepath.Join(dir, txnRoot, e.Name()))
			continue
		}
		if !e.IsDir() || !txnName.MatchString(e.Name()) {
			continue
		}
		t, err := loadTransaction(host, dir, e.Name())
		switch {
		case errors.Is(err, fs.ErrNotExist):
			removeOrQueue(host, filepath.Join(dir, txnRoot, e.Name()))
			continue
		case err != nil:
			return errInstallMixed.With(err, "fix or remove "+filepath.Join(dir, txnRoot, e.Name())+", then run the installer again")
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
	// A run killed after recording the directory but before phase applying
	// leaves an entry no rollback or finish removes.
	(&transaction{host: host, dir: dir}).closeMarker()
	return nil
}

// programAfterRollback is the file that will be at program once every move
// is undone, checked in its place because services are restored before the
// files move back: it replays the move undos in reverse with the conditions
// undo applies, and returns where that file is now, or "" when no file will
// be at program.
func (t *transaction) programAfterRollback(program string) string {
	key := func(p string) string { return strings.ToLower(filepath.Clean(p)) }
	// at maps a path, by key, to where the file that will be there is now.
	at := map[string]string{}
	for _, a := range t.j.Actions {
		if a.Kind != actMove {
			continue
		}
		for _, p := range []string{a.From, a.To} {
			if exists(p) {
				at[key(p)] = p
			}
		}
	}
	if exists(program) {
		at[key(program)] = program
	}
	for i := len(t.j.Actions) - 1; i >= 0; i-- {
		a := t.j.Actions[i]
		if a.Kind != actMove {
			continue
		}
		from, to := key(a.From), key(a.To)
		if src, ok := at[to]; ok {
			if _, taken := at[from]; !taken {
				at[from] = src
				delete(at, to)
			}
		}
	}
	return at[key(program)]
}

func equalFoldPath(a, b string) bool {
	return pathEntryMatches(a, b, func(s string) string { return s })
}

// refuseOtherOpenTransaction refuses while the open-transaction record
// lists another directory, passing the admin-only rule, with a transaction
// at phase applying: its rollback restores the service definitions, so
// this step's changes would be undone. As Windows Installer, no new
// transaction starts until that one is resolved.
func refuseOtherOpenTransaction(host installHost, dir string) error {
	dirs, err := host.listOpen()
	if err != nil {
		return errServiceConfigBusy.With(err, "")
	}
	return refuseOpenTransactionIn(dirs, dir, host.checkInstallDir)
}

// refuseOpenTransactionIn refuses with AG091 when a directory in dirs,
// other than except and passing check (the admin-only rule), holds a
// transaction at phase applying. Only the installer or uninstaller for that
// directory undoes it, so the message names the directory.
func refuseOpenTransactionIn(dirs []string, except string, check func(string) error) error {
	for _, d := range dirs {
		if (except != "" && equalFoldPath(d, except)) || !filepath.IsAbs(d) || check(d) != nil {
			continue
		}
		if txn := openInstallTransaction(d); txn != "" {
			return errServiceConfigBusy.With(nil, fmt.Sprintf("an interrupted install or uninstall (transaction %s) is open in %s; run the Localport installer, or the uninstaller, for that directory, which undoes it first", txn, d))
		}
	}
	return nil
}

// closeMarker removes t.dir from the open-transaction list once no
// transaction in it is still open. A failure only warns: the list then
// names a directory the readers find nothing open in.
func (t *transaction) closeMarker() {
	if openInstallTransaction(t.dir) != "" {
		return
	}
	if err := t.host.markClosed(t.dir); err != nil {
		t.host.warn(fmt.Sprintf("the open-transaction record for %s was not removed: %s", t.dir, userText(err)))
	}
}

// openInstallTransaction names a transaction in dir that an interrupted
// installer or uninstaller left in phase applying, or returns "". Its
// rollback writes the service definitions back from its snapshot, so a
// service change made before that rollback would be undone by it. The
// caller holds the service configuration lock and has checked dir
// admin-only.
func openInstallTransaction(dir string) string {
	entries, err := os.ReadDir(filepath.Join(dir, txnRoot))
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !e.IsDir() || !txnName.MatchString(e.Name()) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, txnRoot, e.Name(), journalFile))
		var j journal
		if err == nil && json.Unmarshal(raw, &j) == nil && j.Phase == phaseApplying {
			return e.Name()
		}
	}
	return ""
}

// removeOrQueue removes the transaction directory path and everything under
// it. A file Windows refuses to delete (an image still running) is renamed
// to a unique leftover name in the parent .localport-txn directory, which a
// running image allows, and queued for deletion at reboot there, so the
// transaction directory itself goes and its id is free for a later
// transaction. What can be neither deleted nor moved is queued in place.
// Failures only warn.
func removeOrQueue(host installHost, path string) {
	var paths []string
	_ = filepath.WalkDir(path, func(p string, _ fs.DirEntry, err error) error {
		if err == nil {
			paths = append(paths, p)
		}
		return nil
	})
	for i := len(paths) - 1; i >= 0; i-- {
		p := paths[i]
		if err := os.Remove(p); err == nil || errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if leftover, err := moveAside(filepath.Dir(path), p); err == nil {
			p = leftover
		}
		if err := host.deleteAtReboot(p); err != nil {
			host.warn(fmt.Sprintf("%s was not deleted and could not be queued for deletion at reboot: %s", p, userText(err)))
		}
	}
}

// leftoverPrefix names a file moved aside by removeOrQueue.
const leftoverPrefix = "leftover-"

// moveAside renames the file p into dir under a unique leftover name.
func moveAside(dir, p string) (string, error) {
	if fi, err := os.Lstat(p); err != nil || fi.IsDir() {
		return "", errors.New("not a file")
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	leftover := filepath.Join(dir, leftoverPrefix+hex.EncodeToString(id))
	if err := os.Rename(p, leftover); err != nil {
		return "", err
	}
	return leftover, nil
}

// removeEmptyOrQueue removes the directory path when it is empty, and
// otherwise queues it for deletion at reboot, which succeeds only if the
// entries queued before it leave it empty.
func removeEmptyOrQueue(host installHost, path string) {
	if err := os.Remove(path); err == nil || errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err := host.deleteAtReboot(path); err != nil {
		host.warn(fmt.Sprintf("%s was not removed: %s", path, userText(err)))
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

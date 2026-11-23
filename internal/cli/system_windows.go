package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/localport/agent/internal/security"
	"github.com/localport/agent/internal/service"
)

// runSystem is `localport system <step>` on Windows (see system.go).
func runSystem(version string, args []string) error {
	return systemExitError(runSystemSteps(context.Background(), windowsInstallHost{}, version, args))
}

type windowsInstallHost struct{}

const (
	// machineEnvironmentKey holds the machine environment, Path included.
	machineEnvironmentKey = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
	// uninstallKey is the Add/Remove Programs entry winget also reads.
	uninstallKey = `Software\Microsoft\Windows\CurrentVersion\Uninstall\Localport`
	// installerKey's openTransactionsValue (REG_MULTI_SZ) lists the
	// install directories with an open transaction, as Windows Installer's
	// InProgress key marks its own. Under HKLM\SOFTWARE only Administrators
	// and SYSTEM can write it; readers only use it to find directories,
	// each checked admin-only before its journal is read.
	productKey            = `SOFTWARE\Localport`
	installerKey          = productKey + `\Installer`
	openTransactionsValue = "OpenTransactions"
	// broadcastTimeout bounds the wait for each top-level window to take the
	// environment change, as setx does.
	broadcastTimeout = 5000 // milliseconds
)

func (windowsInstallHost) elevated() bool { return privileged() }

func (windowsInstallHost) prepareInstallDir(dir string) error {
	if err := security.EnsureInstallDir(dir); err != nil {
		return err
	}
	return security.CheckServiceDir(dir)
}

func (windowsInstallHost) checkInstallDir(dir string) error {
	return security.CheckServiceDir(dir)
}

func (windowsInstallHost) lockServiceConfig(ctx context.Context) (func(), error) {
	return lockServiceConfig(ctx)
}

func (windowsInstallHost) snapshotServices() (json.RawMessage, []string, bool, error) {
	snaps, err := service.SnapshotOwned()
	if err != nil {
		return nil, nil, false, err
	}
	var running []string
	existed := false
	for _, s := range snaps {
		existed = existed || s.Existed
		if s.Running {
			running = append(running, s.Name)
		}
	}
	raw, err := service.MarshalSnapshots(snaps)
	return raw, running, existed, err
}

func (windowsInstallHost) stopServices(ctx context.Context) ([]string, error) {
	return service.StopOwned(ctx)
}

func (windowsInstallHost) startServices(_ context.Context, names []string) error {
	if len(names) == 0 {
		return nil
	}
	return service.StartOwned(names)
}

func (windowsInstallHost) restoreServices(ctx context.Context, raw json.RawMessage, programAt func(string) string) ([]string, error) {
	snaps, err := service.UnmarshalSnapshots(raw)
	if err != nil {
		return nil, err
	}
	return service.RestoreOwned(ctx, snaps, programAt)
}

// installServices runs the `service install` path in process for exe, the
// installed localport.exe; the caller holds the service configuration lock.
func (windowsInstallHost) installServices(_ context.Context, exe string) error {
	return installServiceLocked(currentInvoker(false), exe)
}

func (windowsInstallHost) deleteServices(ctx context.Context) error {
	m, err := newServiceManager()
	if err != nil {
		return err
	}
	if err := m.Uninstall(ctx); err != nil && !errors.Is(err, service.ErrNotInstalled) {
		return err
	}
	return nil
}

func (windowsInstallHost) purge(context.Context) error {
	m, err := newServiceManager()
	if err != nil {
		return err
	}
	return purgeSystemDevices(currentInvoker(false), m, purgeRunLockWait)
}

func (windowsInstallHost) foreignServicesIn(dir string) ([]string, error) {
	return service.ForeignServicesIn(dir)
}

// registryValue is one value of a key, kept with its type for an exact restore.
type registryValue struct {
	Name    string   `json:"name"`
	Type    uint32   `json:"type"`
	String  string   `json:"string,omitempty"`
	Strings []string `json:"strings,omitempty"`
	Integer uint64   `json:"integer,omitempty"`
	Binary  []byte   `json:"binary,omitempty"`
}

func (windowsInstallHost) readUninstallKey() (json.RawMessage, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallKey, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open the uninstall entry: %w", err)
	}
	defer k.Close()
	names, err := k.ReadValueNames(0)
	if err != nil {
		return nil, fmt.Errorf("read the uninstall entry: %w", err)
	}
	var values []registryValue
	for _, name := range names {
		v := registryValue{Name: name}
		_, typ, err := k.GetValue(name, nil)
		if err != nil {
			return nil, fmt.Errorf("read the uninstall entry value %s: %w", name, err)
		}
		v.Type = typ
		switch typ {
		case registry.SZ, registry.EXPAND_SZ:
			v.String, _, err = k.GetStringValue(name)
		case registry.MULTI_SZ:
			v.Strings, _, err = k.GetStringsValue(name)
		case registry.DWORD, registry.QWORD:
			v.Integer, _, err = k.GetIntegerValue(name)
		default:
			v.Binary, _, err = k.GetBinaryValue(name)
		}
		if err != nil {
			return nil, fmt.Errorf("read the uninstall entry value %s: %w", name, err)
		}
		values = append(values, v)
	}
	return json.Marshal(values)
}

func (windowsInstallHost) restoreUninstallKey(raw json.RawMessage) error {
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, uninstallKey); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return fmt.Errorf("delete the uninstall entry: %w", err)
	}
	if raw == nil {
		return nil
	}
	var values []registryValue
	if err := json.Unmarshal(raw, &values); err != nil {
		return fmt.Errorf("read the recorded uninstall entry: %w", err)
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, uninstallKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("create the uninstall entry: %w", err)
	}
	defer k.Close()
	for _, v := range values {
		switch v.Type {
		case registry.SZ:
			err = k.SetStringValue(v.Name, v.String)
		case registry.EXPAND_SZ:
			err = k.SetExpandStringValue(v.Name, v.String)
		case registry.MULTI_SZ:
			err = k.SetStringsValue(v.Name, v.Strings)
		case registry.DWORD:
			err = k.SetDWordValue(v.Name, uint32(v.Integer))
		case registry.QWORD:
			err = k.SetQWordValue(v.Name, v.Integer)
		default:
			err = k.SetBinaryValue(v.Name, v.Binary)
		}
		if err != nil {
			return fmt.Errorf("restore the uninstall entry value %s: %w", v.Name, err)
		}
	}
	return nil
}

func (windowsInstallHost) writeUninstallKey(dir, version string, sizeKB uint32) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, uninstallKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("create the uninstall entry: %w", err)
	}
	defer k.Close()
	uninstaller := `"` + dir + `\uninstall.exe"`
	for name, value := range map[string]string{
		"DisplayName":          "Localport",
		"DisplayVersion":       version,
		"Publisher":            "Localport",
		"InstallLocation":      dir,
		"DisplayIcon":          `"` + dir + `\localport.exe"`,
		"UninstallString":      uninstaller,
		"QuietUninstallString": uninstaller + " /S",
	} {
		if err := k.SetStringValue(name, value); err != nil {
			return fmt.Errorf("write the uninstall entry value %s: %w", name, err)
		}
	}
	for name, value := range map[string]uint32{"NoModify": 1, "NoRepair": 1, "EstimatedSize": sizeKB} {
		if err := k.SetDWordValue(name, value); err != nil {
			return fmt.Errorf("write the uninstall entry value %s: %w", name, err)
		}
	}
	return nil
}

func (windowsInstallHost) readPath() (string, bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, machineEnvironmentKey, registry.QUERY_VALUE)
	if err != nil {
		return "", false, fmt.Errorf("open the machine environment: %w", err)
	}
	defer k.Close()
	value, kind, err := k.GetStringValue("Path")
	if errors.Is(err, registry.ErrNotExist) {
		return "", true, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read the machine Path: %w", err)
	}
	return value, kind == registry.EXPAND_SZ, nil
}

func (windowsInstallHost) writePath(value string, expandable bool) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, machineEnvironmentKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open the machine environment: %w", err)
	}
	defer k.Close()
	if expandable {
		err = k.SetExpandStringValue("Path", value)
	} else {
		err = k.SetStringValue("Path", value)
	}
	if err != nil {
		return fmt.Errorf("write the machine Path: %w", err)
	}
	return nil
}

var procSendMessageTimeoutW = windows.NewLazySystemDLL("user32.dll").NewProc("SendMessageTimeoutW")

// broadcastEnvironment tells running programs (Explorer, new shells) that
// the environment changed, as WM_SETTINGCHANGE "Environment". A broadcast
// returns 0 when any one window fails or times out, which says nothing about
// the saved change, so the caller only warns.
func (windowsInstallHost) broadcastEnvironment() error {
	const (
		hwndBroadcast   = 0xffff
		wmSettingChange = 0x001a
		smtoAbortIfHung = 0x0002
	)
	env, err := windows.UTF16PtrFromString("Environment")
	if err != nil {
		return err
	}
	var result uintptr
	r, _, callErr := procSendMessageTimeoutW.Call(hwndBroadcast, wmSettingChange, 0,
		uintptr(unsafe.Pointer(env)), smtoAbortIfHung, broadcastTimeout, uintptr(unsafe.Pointer(&result)))
	if r == 0 {
		return fmt.Errorf("broadcast the environment change: %w", callErr)
	}
	return nil
}

func (windowsInstallHost) expand(s string) string {
	expanded, err := registry.ExpandString(s)
	if err != nil {
		return s
	}
	return expanded
}

// openTransactionDirs reads the open-transaction list; a missing key or
// value is an empty list.
func openTransactionDirs() ([]string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, installerKey, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open the installer record: %w", err)
	}
	defer k.Close()
	dirs, _, err := k.GetStringsValue(openTransactionsValue)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the open-transaction record: %w", err)
	}
	return dirs, nil
}

// writeOpenTransactionDirs writes the list; an empty list removes the
// installer key, which holds nothing else, and then the Localport key when
// nothing else is in it, so an uninstall leaves no key behind.
func writeOpenTransactionDirs(dirs []string) error {
	if len(dirs) == 0 {
		if err := registry.DeleteKey(registry.LOCAL_MACHINE, installerKey); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return fmt.Errorf("remove the open-transaction record: %w", err)
		}
		return removeEmptyKey(productKey)
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, installerKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("create the installer record: %w", err)
	}
	defer k.Close()
	if err := k.SetStringsValue(openTransactionsValue, dirs); err != nil {
		return fmt.Errorf("write the open-transaction record: %w", err)
	}
	return nil
}

func removeEmptyKey(path string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return &fs.PathError{Op: "open", Path: path, Err: err}
	}
	info, err := k.Stat()
	k.Close()
	if err != nil {
		return &fs.PathError{Op: "read", Path: path, Err: err}
	}
	if info.SubKeyCount > 0 || info.ValueCount > 0 {
		return nil
	}
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, path); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return &fs.PathError{Op: "remove", Path: path, Err: err}
	}
	return nil
}

func (windowsInstallHost) listOpen() ([]string, error) { return openTransactionDirs() }

func (windowsInstallHost) markOpen(dir string) error {
	dirs, err := openTransactionDirs()
	if err != nil {
		return err
	}
	if slices.ContainsFunc(dirs, func(d string) bool { return equalFoldPath(d, dir) }) {
		return nil
	}
	return writeOpenTransactionDirs(append(dirs, dir))
}

func (windowsInstallHost) markClosed(dir string) error {
	dirs, err := openTransactionDirs()
	if err != nil {
		return err
	}
	kept := slices.DeleteFunc(slices.Clone(dirs), func(d string) bool { return equalFoldPath(d, dir) })
	if len(kept) == len(dirs) {
		return nil
	}
	return writeOpenTransactionDirs(kept)
}

// deleteAtReboot queues path for deletion at the next start of Windows
// (PendingFileRenameOperations), the way Windows Installer removes a file
// still in use.
func (windowsInstallHost) deleteAtReboot(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}

func (windowsInstallHost) warn(msg string) {
	fmt.Fprintf(os.Stderr, "%s warning: %s\n", time.Now().UTC().Format(time.RFC3339), msg)
}

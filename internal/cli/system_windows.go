package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/localport/agent/internal/security"
	"github.com/localport/agent/internal/service"
)

// runSystem is `localport system <step>` on Windows (see system.go).
func runSystem(args []string) error {
	return runSystemSteps(context.Background(), windowsInstallHost{}, args)
}

// windowsInstallHost is the installHost of a Windows machine.
type windowsInstallHost struct{}

// machineEnvironmentKey holds the machine environment, Path included.
const machineEnvironmentKey = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`

// broadcastTimeout bounds the wait for each top-level window to take the
// environment change, as setx does.
const broadcastTimeout = 5000 // milliseconds

func (windowsInstallHost) elevated() bool { return privileged() }

func (windowsInstallHost) prepareInstallDir(dir string) error {
	if err := security.EnsureInstallDir(dir); err != nil {
		return err
	}
	return security.CheckServiceDir(dir)
}

func (windowsInstallHost) stopServices(ctx context.Context) ([]string, error) {
	return service.StopOwned(ctx)
}

func (windowsInstallHost) startServices(_ context.Context, names []string) error {
	return service.StartOwned(names)
}

func (windowsInstallHost) servicesInstalled() (bool, error) {
	m, installed, err := installedDeviceService()
	if m == nil && err == nil {
		return false, nil
	}
	return installed, err
}

// reregister runs `service install` from the installed localport.exe, which
// rewrites both service definitions to its own path and restarts them; it
// spends no token.
func (windowsInstallHost) reregister(ctx context.Context, dir string) error {
	cmd := exec.CommandContext(ctx, filepath.Join(dir, "localport.exe"), "service", "install")
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run()
}

func (windowsInstallHost) foreignServicesIn(dir string) ([]string, error) {
	return service.ForeignServicesIn(dir)
}

func (windowsInstallHost) uninstallServices(purge bool) error {
	return uninstallService(currentInvoker(false), purge)
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
// the environment changed, as WM_SETTINGCHANGE "Environment".
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

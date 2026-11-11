package cli

import (
	"context"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// serviceConfigMutex serializes every writer of the device service
// definitions: connect, service install and uninstall, and the installer's
// transaction steps. Creating a Global object needs SeCreateGlobalPrivilege,
// which standard users lack, and the DACL admits only SYSTEM and
// Administrators, so no unprivileged process can hold it.
const serviceConfigMutex = `Global\LocalportServiceConfig`

// serviceConfigLockWait bounds the wait for another writer.
var serviceConfigLockWait = 2 * time.Minute

// lockServiceConfig takes the service configuration mutex. abandoned reports
// that its previous holder exited without releasing it, so an install
// transaction it ran may be open. The mutex belongs to the OS thread, so the
// calling goroutine stays on its thread until unlock.
func lockServiceConfig(ctx context.Context) (unlock func(), abandoned bool, err error) {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return nil, false, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, err := windows.UTF16PtrFromString(serviceConfigMutex)
	if err != nil {
		return nil, false, err
	}
	runtime.LockOSThread()
	h, err := windows.CreateMutex(&sa, false, name)
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		runtime.UnlockOSThread()
		return nil, false, fmt.Errorf("open %s: %w", serviceConfigMutex, err)
	}
	deadline := time.Now().Add(serviceConfigLockWait)
	for {
		ev, err := windows.WaitForSingleObject(h, 250)
		switch {
		case err != nil:
			_ = windows.CloseHandle(h)
			runtime.UnlockOSThread()
			return nil, false, fmt.Errorf("wait for %s: %w", serviceConfigMutex, err)
		case ev == windows.WAIT_OBJECT_0 || ev == windows.WAIT_ABANDONED:
			return func() {
				_ = windows.ReleaseMutex(h)
				_ = windows.CloseHandle(h)
				runtime.UnlockOSThread()
			}, ev == windows.WAIT_ABANDONED, nil
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			_ = windows.CloseHandle(h)
			runtime.UnlockOSThread()
			return nil, false, fmt.Errorf("%w: another installer, connect or service command holds %s", errServiceConfigBusy, serviceConfigMutex)
		}
	}
}

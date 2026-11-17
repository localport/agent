package cli

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/localport/agent/internal/security"
)

// The service configuration mutex serializes every writer of the device
// service definitions: up, service install and uninstall, and the
// installer's transaction steps. It lives in a private namespace whose
// boundary requires the Administrators SID, so only an elevated
// Administrator (or SYSTEM) can create or open it; no other account can
// create the name first and hold it. The namespace's DACL admits SYSTEM and
// Administrators only.
const (
	serviceConfigNamespace = "LocalportServiceConfig"
	serviceConfigMutex     = serviceConfigNamespace + `\ServiceConfig`
	serviceConfigSDDL      = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
	// serviceConfigNamespaceTries bounds the create-else-open loop, which
	// repeats only when the namespace closes between the two calls.
	serviceConfigNamespaceTries = 8
)

// serviceConfigLockWait bounds the wait for another writer.
var serviceConfigLockWait = 2 * time.Minute

// errServiceConfigHeld is the wait for another writer running out, as
// distinct from failing to open the lock at all.
var errServiceConfigHeld = errors.New("another installer, up or service command holds the service configuration mutex")

// serviceConfigWaiting, when set by a test, runs once a writer holds its
// namespace and mutex handles and starts waiting.
var serviceConfigWaiting func()

var (
	kernel32                       = windows.NewLazySystemDLL("kernel32.dll")
	procCreateBoundaryDescriptorW  = kernel32.NewProc("CreateBoundaryDescriptorW")
	procAddSIDToBoundaryDescriptor = kernel32.NewProc("AddSIDToBoundaryDescriptor")
	procDeleteBoundaryDescriptor   = kernel32.NewProc("DeleteBoundaryDescriptor")
	procCreatePrivateNamespaceW    = kernel32.NewProc("CreatePrivateNamespaceW")
	procOpenPrivateNamespaceW      = kernel32.NewProc("OpenPrivateNamespaceW")
	procClosePrivateNamespace      = kernel32.NewProc("ClosePrivateNamespace")
)

// lockServiceConfig takes the service configuration mutex. A mutex its last
// holder abandoned is taken like a released one: every step that replays
// journals recovers them under the lock, and lockServiceDefinitions refuses
// while one is open. The mutex belongs to the OS thread, so the calling
// goroutine stays on its thread until unlock. Every failure carries AG091.
func lockServiceConfig(ctx context.Context) (func(), error) {
	runtime.LockOSThread()
	release, err := takeServiceConfigMutex(ctx)
	if err != nil {
		runtime.UnlockOSThread()
		return nil, errServiceConfigBusy.With(err, "")
	}
	return func() {
		release()
		runtime.UnlockOSThread()
	}, nil
}

// lockServiceDefinitions is lockServiceConfig for up and the service
// commands. It refuses while an interrupted installer transaction is open in
// any directory the open-transaction record lists: that transaction's
// rollback restores the service definitions it recorded and would undo
// this command's change.
func lockServiceDefinitions(ctx context.Context) (func(), error) {
	unlock, err := lockServiceConfig(ctx)
	if err != nil {
		return nil, err
	}
	dirs, err := openTransactionDirs()
	if err != nil {
		unlock()
		return nil, errServiceConfigBusy.With(err, "")
	}
	if err := refuseOpenTransactionIn(dirs, "", security.CheckServiceDir); err != nil {
		unlock()
		return nil, err
	}
	return unlock, nil
}

// takeServiceConfigMutex opens the private namespace and waits for the
// mutex in it. The namespace handle stays open while the mutex is held.
func takeServiceConfigMutex(ctx context.Context) (func(), error) {
	ns, err := openServiceConfigNamespace()
	if err != nil {
		return nil, err
	}
	closeNamespace := func() { _, _, _ = procClosePrivateNamespace.Call(ns, 0) }
	sd, err := windows.SecurityDescriptorFromString(serviceConfigSDDL)
	if err != nil {
		closeNamespace()
		return nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, err := windows.UTF16PtrFromString(serviceConfigMutex)
	if err != nil {
		closeNamespace()
		return nil, err
	}
	h, err := windows.CreateMutex(&sa, false, name)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		closeNamespace()
		return nil, fmt.Errorf("open the service configuration mutex: %w", err)
	}
	release := func() {
		_ = windows.CloseHandle(h)
		closeNamespace()
	}
	if serviceConfigWaiting != nil {
		serviceConfigWaiting()
	}
	deadline := time.Now().Add(serviceConfigLockWait)
	for {
		ev, err := windows.WaitForSingleObject(h, 250)
		switch {
		case err != nil:
			release()
			return nil, fmt.Errorf("wait for the service configuration mutex: %w", err)
		case ev == windows.WAIT_OBJECT_0 || ev == windows.WAIT_ABANDONED:
			return func() {
				_ = windows.ReleaseMutex(h)
				release()
			}, nil
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			release()
			return nil, errServiceConfigHeld
		}
	}
}

// openServiceConfigNamespace creates the private namespace, or opens it when
// another writer created it first. The loop repeats when the namespace
// closed between a failed create and the open.
func openServiceConfigNamespace() (uintptr, error) {
	alias, err := windows.UTF16PtrFromString(serviceConfigNamespace)
	if err != nil {
		return 0, err
	}
	bd, _, callErr := procCreateBoundaryDescriptorW.Call(uintptr(unsafe.Pointer(alias)), 0)
	if bd == 0 {
		return 0, fmt.Errorf("create the boundary descriptor: %w", callErr)
	}
	defer func() { _, _, _ = procDeleteBoundaryDescriptor.Call(bd) }()
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return 0, err
	}
	if r, _, callErr := procAddSIDToBoundaryDescriptor.Call(uintptr(unsafe.Pointer(&bd)), uintptr(unsafe.Pointer(admins))); r == 0 {
		return 0, fmt.Errorf("add the Administrators SID to the boundary descriptor: %w", callErr)
	}
	sd, err := windows.SecurityDescriptorFromString(serviceConfigSDDL)
	if err != nil {
		return 0, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	for range serviceConfigNamespaceTries {
		ns, _, createErr := procCreatePrivateNamespaceW.Call(uintptr(unsafe.Pointer(&sa)), bd, uintptr(unsafe.Pointer(alias)))
		if ns != 0 {
			return ns, nil
		}
		if !errors.Is(createErr, windows.ERROR_ALREADY_EXISTS) {
			return 0, fmt.Errorf("create the service configuration namespace: %w", createErr)
		}
		ns, _, openErr := procOpenPrivateNamespaceW.Call(bd, uintptr(unsafe.Pointer(alias)))
		if ns != 0 {
			return ns, nil
		}
		if !errors.Is(openErr, windows.ERROR_PATH_NOT_FOUND) {
			return 0, fmt.Errorf("open the service configuration namespace: %w", openErr)
		}
	}
	return 0, errors.New("the service configuration namespace kept closing between create and open")
}

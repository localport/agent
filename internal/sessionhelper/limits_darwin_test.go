//go:build cgo && darwin

package sessionhelper

import (
	"syscall"
	"unsafe"
)

// setNofileBehindGo sets RLIMIT_NOFILE with a raw setrlimit, as pam_limits'
// call from C does: syscall.Setrlimit would also clear the syscall
// package's saved limit.
func setNofileBehindGo(r *syscall.Rlimit) error {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_SETRLIMIT, syscall.RLIMIT_NOFILE, uintptr(unsafe.Pointer(r)), 0); errno != 0 {
		return errno
	}
	return nil
}

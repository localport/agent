//go:build cgo && pam && linux

package sessionhelper

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// setNofileBehindGo sets RLIMIT_NOFILE with a raw prlimit64, as pam_limits'
// setrlimit from C does: the syscall package's wrappers would also clear its
// saved limit.
func setNofileBehindGo(r *syscall.Rlimit) error {
	if _, _, errno := unix.RawSyscall6(unix.SYS_PRLIMIT64, 0, unix.RLIMIT_NOFILE, uintptr(unsafe.Pointer(r)), 0, 0, 0); errno != 0 {
		return errno
	}
	return nil
}

//go:build !windows

package security

import (
	"os"
	"syscall"
)

// TryLockFile takes an exclusive lock on f without blocking. It reports false when
// another process holds it. The OS releases the lock when the holder exits.
func TryLockFile(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	switch err {
	case nil:
		return true, nil
	case syscall.EWOULDBLOCK:
		return false, nil
	default:
		return false, err
	}
}

// UnlockFile releases a lock TryLockFile took.
func UnlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

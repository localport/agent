//go:build windows

package security

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// TryLockFile takes an exclusive lock on f without blocking. It reports false when
// another process holds it. The OS releases the lock when the holder exits.
func TryLockFile(f *os.File) (bool, error) {
	var overlapped windows.Overlapped
	err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &overlapped)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return false, nil
	}
	return false, err
}

// UnlockFile releases a lock TryLockFile took.
func UnlockFile(f *os.File) error {
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &overlapped)
}

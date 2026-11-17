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
	return tryLockFileEx(f, windows.LOCKFILE_EXCLUSIVE_LOCK)
}

// TryLockFileShared takes a shared lock on f without blocking. Shared holders
// exclude only an exclusive holder. It reports false when one holds it.
func TryLockFileShared(f *os.File) (bool, error) {
	return tryLockFileEx(f, 0)
}

func tryLockFileEx(f *os.File, flags uint32) (bool, error) {
	var overlapped windows.Overlapped
	err := windows.LockFileEx(windows.Handle(f.Fd()),
		flags|windows.LOCKFILE_FAIL_IMMEDIATELY,
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

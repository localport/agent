package config

import (
	"os"
	"path/filepath"

	"github.com/localport/agent/internal/security"
)

// openRunLock opens run.lock, which LockRunFile both locks and records the
// holder in. Every handle to it is opened without delete sharing, so it
// cannot be deleted while a holder has it open and no second process can
// lock a new file beside the holder.
func openRunLock(f LocalConfigFile) (lock, record *os.File, err error) {
	path := f.RunLockPath()
	if !f.System {
		if err := security.EnsurePrivateDir(f.Base, filepath.Dir(f.Path), f.FollowBase); err != nil {
			return nil, nil, errLocalUnusable.With(err, f.Path)
		}
		lock, err = security.OpenPinnedLockFile(path)
	} else {
		// security.OpenSystemLock and OpenSystemRunLock open without delete
		// sharing.
		lock, err = openLock(f, path)
	}
	if err != nil {
		return nil, nil, err
	}
	return lock, lock, nil
}

// LockPath is the lock file LockLocal holds beside the config.
func (f LocalConfigFile) LockPath() string { return f.Path + ".lock" }

// openConfigLock opens LockLocal's lock file without delete sharing, so it
// cannot be deleted while held: root-only for the system config (openLock).
func openConfigLock(f LocalConfigFile) (*os.File, error) {
	if !f.System {
		if err := security.EnsurePrivateDir(f.Base, filepath.Dir(f.Path), f.FollowBase); err != nil {
			return nil, err
		}
		return security.OpenPinnedLockFile(f.LockPath())
	}
	return openLock(f, f.LockPath())
}

// RunLockHeld reports whether a process holds the run lock of f, for a status
// probe that changes nothing: it takes and at once drops a shared lock on
// run.lock and creates nothing. An account that cannot open run.lock gets the
// open error.
func RunLockHeld(f LocalConfigFile) (bool, error) {
	lock, err := os.Open(f.RunLockPath())
	if err != nil {
		return false, err
	}
	defer lock.Close()
	free, err := security.TryLockFileShared(lock)
	if err != nil {
		return false, err
	}
	if free {
		return false, security.UnlockFile(lock)
	}
	return true, nil
}

//go:build !windows

package config

import (
	"os"
	"path/filepath"

	"github.com/localport/agent/internal/security"
)

// openRunLock opens what LockRunFile locks and the file it records the holder
// in. The lock is on the device config directory itself, which cannot be
// removed while it holds the config, so deleting run.lock never lets a second
// process lock a new file beside a holder. run.lock (opened as openLock does,
// root creating and securing it) records the holder's PID.
func openRunLock(f LocalConfigFile) (lock, record *os.File, err error) {
	record, err = openLock(f, f.RunLockPath())
	if err != nil {
		return nil, nil, err
	}
	lock, err = security.OpenLockDir(runLockDir(f))
	if err != nil {
		_ = record.Close()
		return nil, nil, err
	}
	return lock, record, nil
}

// runLockDir is the path the run lock opens: the config directory, through a
// trailing "." when it is a base the config follows (FollowBase, as
// EnsurePrivateDir follows it), so OpenLockDir's no-follow open resolves a
// linked LOCALPORT_HOME or ~/.localport and still refuses a linked system
// directory.
func runLockDir(f LocalConfigFile) string {
	dir := filepath.Dir(f.Path)
	if f.FollowBase && filepath.Clean(dir) == filepath.Clean(f.Base) {
		return dir + string(filepath.Separator) + "."
	}
	return dir
}

// LockPath is the config lock LockLocal holds: a directory beside the config,
// kept non-empty by its marker file (configLockMarker) so neither rm nor rmdir
// removes it while it is held.
func (f LocalConfigFile) LockPath() string { return f.Path + ".lock.d" }

// configLockMarker keeps the config lock directory non-empty.
const configLockMarker = "lock"

// openConfigLock creates or secures the config lock directory (LockPath) and
// its marker and opens the directory for LockLocal's flock. For the system
// config it is root:AgentGroup 0700 with a 0600 marker, so only root, whom
// LockLocal requires, can open it.
func openConfigLock(f LocalConfigFile) (*os.File, error) {
	dir := f.LockPath()
	marker := filepath.Join(dir, configLockMarker)
	var m *os.File
	if f.System {
		gid, err := ensureSystemDir(f)
		if err != nil {
			return nil, err
		}
		if err := security.EnsureSystemLockDir(dir, gid); err != nil {
			return nil, err
		}
		if m, err = security.OpenSystemLock(marker, gid, security.SystemConfigLockPerm); err != nil {
			return nil, err
		}
	} else {
		if err := security.EnsurePrivateDir(f.Base, dir, f.FollowBase); err != nil {
			return nil, err
		}
		var err error
		if m, err = security.OpenLockFile(marker); err != nil {
			return nil, err
		}
	}
	if err := m.Close(); err != nil {
		return nil, err
	}
	return security.OpenLockDir(dir)
}

// RunLockHeld reports whether a process holds the run lock of f, for a status
// probe that changes nothing: it takes and at once drops a shared lock on the
// config directory and creates nothing. An account that cannot open the
// directory gets the open error.
func RunLockHeld(f LocalConfigFile) (bool, error) {
	dir, err := security.OpenLockDir(runLockDir(f))
	if err != nil {
		return false, err
	}
	defer dir.Close()
	free, err := security.TryLockFileShared(dir)
	if err != nil {
		return false, err
	}
	if free {
		return false, security.UnlockFile(dir)
	}
	return true, nil
}

// AdoptRunLock checks that lock, a descriptor the parent passed, is the run
// lock of f (the device config directory, openRunLock) and that it holds the
// lock. The parent took it (LockRunFile) and releases it after this process
// exits, so the adopter only closes lock and never unlocks it: unlocking any
// duplicate releases the lock for all of them.
func AdoptRunLock(f LocalConfigFile, lock *os.File) error {
	dir := filepath.Dir(f.Path)
	got, err := lock.Stat()
	if err != nil {
		return errLocalUnusable.With(err, "inspect the run lock descriptor")
	}
	want, err := os.Lstat(runLockDir(f))
	if err != nil {
		return errLocalUnusable.With(err, "inspect "+dir)
	}
	if !os.SameFile(got, want) {
		return errLocalUnusable.With(nil, "the run lock descriptor is not "+dir)
	}
	// Locking a description that already holds the lock succeeds at once.
	held, err := security.TryLockFile(lock)
	if err != nil {
		return errLocalUnusable.With(err, "lock "+dir)
	}
	if !held {
		return ErrRunLocked.With(nil, "held by the process recorded in "+f.RunLockPath())
	}
	return nil
}

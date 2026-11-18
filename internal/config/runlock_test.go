package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/localport/agent/internal/security"
)

func testRunFile(t *testing.T) LocalConfigFile {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "localport-device")
	return LocalConfigFile{Path: filepath.Join(dir, "agent.yaml"), Base: dir}
}

// A second LockRun is refused at once while the first holds run.lock, and
// succeeds after the holder releases it.
func TestLockRunRefusesASecondHolder(t *testing.T) {
	f := testRunFile(t)
	release, err := LockRun(f, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LockRun(f, 0); !errors.Is(err, ErrRunLocked) {
		t.Fatalf("second LockRun = %v, want ErrRunLocked", err)
	}
	if err := release(); err != nil {
		t.Fatalf("release = %v", err)
	}
	again, err := LockRun(f, 0)
	if err != nil {
		t.Fatalf("LockRun after release = %v", err)
	}
	if err := again(); err != nil {
		t.Fatal(err)
	}
}

// Removing run.lock while a holder has it must not let a second process take
// the devices. On Windows the removal fails (run.lock is open without delete
// sharing); on Linux and macOS it succeeds, but the lock is on the config
// directory, so the second LockRun is refused either way.
func TestLockRunRefusedAfterTheLockFileIsRemoved(t *testing.T) {
	f := testRunFile(t)
	release, err := LockRun(f, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = release() }()
	removable := runtime.GOOS != "windows"
	if err := os.Remove(f.RunLockPath()); (err == nil) != removable {
		t.Fatalf("remove %s while held = %v, want removable %v", f.RunLockPath(), err, removable)
	}
	second, err := LockRun(f, 0)
	if err == nil {
		_ = second()
	}
	if !errors.Is(err, ErrRunLocked) {
		t.Fatalf("LockRun after run.lock was removed under its holder = %v, want ErrRunLocked", err)
	}
}

// The config lock cannot be deleted while LockLocal holds it, so no second
// writer can lock a new one beside the holder; the lock stays held.
func TestLockLocalCannotBeRemovedWhileHeld(t *testing.T) {
	f := testRunFile(t)
	release, err := LockLocal(f)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := os.Remove(f.LockPath()); err == nil {
		t.Fatalf("removed %s while LockLocal held it", f.LockPath())
	}
	lock, err := os.Open(f.LockPath())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if free, err := security.TryLockFile(lock); err != nil || free {
		t.Fatalf("config lock after the removal attempt: free %v, %v; want held", free, err)
	}
}

// A waiting LockRun takes run.lock once the holder releases it within the
// wait.
func TestLockRunWaitsForTheHolder(t *testing.T) {
	f := testRunFile(t)
	release, err := LockRun(f, 0)
	if err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(300*time.Millisecond, func() { _ = release() })
	start := time.Now()
	waited, err := LockRun(f, 10*time.Second)
	if err != nil {
		t.Fatalf("waiting LockRun = %v", err)
	}
	defer func() { _ = waited() }()
	if time.Since(start) < 200*time.Millisecond {
		t.Fatal("LockRun took the lock while the holder still had it")
	}
}

// run.lock and agent.yaml.lock are separate locks.
func TestLockRunIsSeparateFromLockLocal(t *testing.T) {
	f := testRunFile(t)
	release, err := LockRun(f, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = release() }()
	unlock, err := LockLocal(f)
	if err != nil {
		t.Fatalf("LockLocal beside run.lock = %v", err)
	}
	unlock()
}

// The holder records its PID, which RunLockHolder reads while the lock is
// held.
func TestLockRunRecordsTheHolderPID(t *testing.T) {
	f := testRunFile(t)
	release, err := LockRun(f, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = release() }()
	if pid, err := RunLockHolder(f); err != nil || pid != os.Getpid() {
		t.Fatalf("RunLockHolder = %d, %v, want %d", pid, err, os.Getpid())
	}
}

// Release clears the record before unlocking, so a process that takes the
// lock next never shows its predecessor's PID before it records its own:
// up's check would otherwise match a stopped service's PID that its
// manager still reports.
func TestLockRunReleaseClearsTheHolderPID(t *testing.T) {
	f := testRunFile(t)
	release, err := LockRun(f, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if pid, err := RunLockHolder(f); err != nil || pid != 0 {
		t.Fatalf("RunLockHolder after release = %d, %v, want 0", pid, err)
	}
}

// A cancelled context ends the wait for run.lock at once.
func TestLockRunContextEndsTheWaitWithTheContext(t *testing.T) {
	f := testRunFile(t)
	release, err := LockRun(f, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = release() }()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	if _, err := LockRunContext(ctx, f, 10*time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("LockRunContext after cancel = %v, want context.Canceled", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the wait outlived its context")
	}
}

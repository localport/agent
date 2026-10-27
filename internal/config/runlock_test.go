package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
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

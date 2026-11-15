package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

// crashChildEnv makes the test binary a child that arms crash output in the
// directory the variable names and then dies of a panic.
const crashChildEnv = "LOCALPORT_TEST_CRASH_CHILD_DIR"

func TestMain(m *testing.M) {
	if dir := os.Getenv(crashChildEnv); dir != "" {
		if err := armCrashOutput(dir); err != nil {
			fmt.Fprintln(os.Stderr, "arm:", err)
			os.Exit(3)
		}
		go func() { panic("crash capture test panic") }()
		time.Sleep(10 * time.Second)
		os.Exit(4)
	}
	os.Exit(m.Run())
}

// A fatal error after armCrashOutput lands in current.crash.
func TestArmedCrashOutputReceivesAFatalPanic(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), crashChildEnv+"="+dir)
	if err := cmd.Run(); err == nil {
		t.Fatal("the child did not die")
	}
	raw, err := os.ReadFile(filepath.Join(dir, crashFile))
	if err != nil || !strings.Contains(string(raw), "panic: crash capture test panic") {
		t.Fatalf("current.crash = %q, %v; want the panic", raw, err)
	}
}

func writeCrash(t *testing.T, dir, name, body string, at time.Time) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, at, at); err != nil {
		t.Fatal(err)
	}
}

// disarmCrashOutput hands the runtime no crash file once the test ends. The
// runtime keeps the armed file open, which on Windows blocks removing the
// test's directory.
func disarmCrashOutput(t *testing.T) {
	t.Cleanup(func() {
		if err := debug.SetCrashOutput(nil, debug.CrashOptions{}); err != nil {
			t.Errorf("disarm crash output: %v", err)
		}
	})
}

// A start after a crash keeps it under its UTC time, reports it once without
// its text, keeps the five newest, and arms an empty current.crash.
func TestCaptureCrashesRotatesReportsAndKeepsFive(t *testing.T) {
	dir := t.TempDir()
	disarmCrashOutput(t)
	at := time.Date(2026, 11, 12, 15, 30, 0, 0, time.UTC)
	for i := range 5 {
		writeCrash(t, dir, at.Add(-time.Duration(i+1)*time.Hour).Format(crashTimeLayout)+".crash", "old", at.Add(-time.Duration(i+1)*time.Hour))
	}
	writeCrash(t, dir, at.Format(crashTimeLayout)+".crash", "same second", at)
	writeCrash(t, dir, crashFile, "panic: secret value in a stack\n", at)

	var reports, warnings []string
	captureCrashes(dir, "localport-device", "1.4.0", func(string) error { return nil },
		func(s string) { warnings = append(warnings, s) }, func(s string) { reports = append(reports, s) })

	moved := filepath.Join(dir, "20261112T153000Z-1.crash")
	if raw, err := os.ReadFile(moved); err != nil || !strings.Contains(string(raw), "secret value") {
		t.Fatalf("rotated crash %s = %q, %v", moved, raw, err)
	}
	if len(reports) != 1 || strings.Contains(reports[0], "secret") ||
		!strings.Contains(reports[0], moved) || !strings.Contains(reports[0], "1.4.0") ||
		!strings.Contains(reports[0], "localport-device") || !strings.Contains(reports[0], "2026-11-12T15:30:00Z") {
		t.Fatalf("reports = %q, want one naming time, version, service and file, without the crash text", reports)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %q", warnings)
	}
	entries, err := filepath.Glob(filepath.Join(dir, "2*.crash"))
	if err != nil || len(entries) != keptCrashes {
		t.Fatalf("kept %d crash files (%v), want %d", len(entries), err, keptCrashes)
	}
	if fi, err := os.Stat(filepath.Join(dir, crashFile)); err != nil || fi.Size() != 0 {
		t.Fatalf("current.crash after start = %v, %v; want empty", fi, err)
	}

	// A start with nothing written reports nothing.
	reports = nil
	captureCrashes(dir, "localport-device", "1.4.0", func(string) error { return nil }, func(string) {}, func(s string) { reports = append(reports, s) })
	if len(reports) != 0 {
		t.Fatalf("reports after a clean run = %q", reports)
	}
}

// An untrusted directory disables capture with a warning and touches nothing.
func TestCaptureCrashesSkipsAnUntrustedDirectory(t *testing.T) {
	dir := t.TempDir()
	writeCrash(t, dir, crashFile, "panic: x\n", time.Now())
	var warnings []string
	captureCrashes(dir, "localport-session", "1.4.0", func(string) error { return errors.New("foreign owner") },
		func(s string) { warnings = append(warnings, s) }, func(string) { t.Fatal("reported from an untrusted directory") })
	if len(warnings) != 1 || !strings.Contains(warnings[0], "foreign owner") {
		t.Fatalf("warnings = %q", warnings)
	}
	if raw, _ := os.ReadFile(filepath.Join(dir, crashFile)); string(raw) != "panic: x\n" {
		t.Fatal("an untrusted directory was changed")
	}
}

// A crash that cannot be kept stays as it is: arming would truncate it.
func TestCaptureCrashesLeavesACrashItCannotKeep(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a directory the test cannot rename in: a Unix non-root run")
	}
	dir := t.TempDir()
	writeCrash(t, dir, crashFile, "panic: x\n", time.Now())
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	var warnings []string
	captureCrashes(dir, "localport-device", "1.4.0", func(string) error { return nil },
		func(s string) { warnings = append(warnings, s) }, func(string) { t.Fatal("reported a crash it did not keep") })
	if raw, _ := os.ReadFile(filepath.Join(dir, crashFile)); string(raw) != "panic: x\n" {
		t.Fatalf("current.crash = %q, want the unkept crash", raw)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "crash capture is off") {
		t.Fatalf("warnings = %q", warnings)
	}
}

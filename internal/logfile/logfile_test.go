//go:build linux || darwin

package logfile

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The test re-runs itself as a child so the descriptor moves happen in a
// process of their own: LOGFILE_CHILD names the log, LOGFILE_ROUNDS how many
// rotations to force.
func TestMain(m *testing.M) {
	if path := os.Getenv("LOGFILE_CHILD"); path != "" {
		rounds, _ := strconv.Atoi(os.Getenv("LOGFILE_ROUNDS"))
		l, err := Open(path)
		if err != nil {
			os.Exit(3)
		}
		l.max = 1
		for i := 0; i <= rounds; i++ {
			os.Stderr.WriteString("line " + strconv.Itoa(i) + "\n")
			if i < rounds {
				if err := l.RotateIfLarge(); err != nil {
					os.Exit(4)
				}
			}
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// Stderr goes to the file; each rotation shifts the copies and keeps at most
// MaxBackups of them, oldest dropped.
func TestRotationKeepsTheNewestBackups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")
	rounds := MaxBackups + 2
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "LOGFILE_CHILD="+path, "LOGFILE_ROUNDS="+strconv.Itoa(rounds))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v %s", err, out)
	}
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	if got := read(path); got != "line "+strconv.Itoa(rounds) {
		t.Fatalf("current file %q", got)
	}
	for i := 1; i <= MaxBackups; i++ {
		if got, want := read(path+"."+strconv.Itoa(i)), "line "+strconv.Itoa(rounds-i); got != want {
			t.Fatalf("%s.%d = %q, want %q", path, i, got, want)
		}
	}
	if _, err := os.Stat(path + "." + strconv.Itoa(MaxBackups+1)); !os.IsNotExist(err) {
		t.Fatalf("a backup past MaxBackups exists: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("log mode %v, %v; want 0600", fi.Mode(), err)
	}
}

//go:build cgo && (linux || darwin)

package sessionhelper

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// fileLimitTestStage makes a re-executed test binary run runFileLimitStage.
const fileLimitTestStage = "LOCALPORT_FILE_LIMIT_STAGE"

// runFileLimitStage lowers its own soft RLIMIT_NOFILE behind the syscall
// package's back, as pam_limits does from C, applies keepPAMFileLimit when
// the stage is "keep", and prints the soft limit a child sees, then the
// lowered value.
func runFileLimitStage() int {
	var before syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &before); err != nil {
		fmt.Println(err)
		return 1
	}
	pamSet := before
	if os.Getenv(fileLimitTestStage) == "unchanged" {
		if err := keepPAMFileLimit(before); err != nil {
			fmt.Println(err)
			return 1
		}
		out, err := exec.Command("/bin/sh", "-c", "ulimit -n").Output()
		if err != nil {
			fmt.Println(err)
			return 1
		}
		fmt.Println(strings.TrimSpace(string(out)))
		return 0
	}
	pamSet.Cur = 200
	if err := setNofileBehindGo(&pamSet); err != nil {
		fmt.Println(err)
		return 1
	}
	if os.Getenv(fileLimitTestStage) == "keep" {
		if err := keepPAMFileLimit(before); err != nil {
			fmt.Println(err)
			return 1
		}
	}
	out, err := exec.Command("/bin/sh", "-c", "ulimit -n").Output()
	if err != nil {
		fmt.Println(err)
		return 1
	}
	fmt.Println(strings.TrimSpace(string(out)), pamSet.Cur)
	return 0
}

// A soft open file limit set by a PAM module reaches the child.
func TestKeepPAMFileLimitReachesTheChild(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), fileLimitTestStage+"=keep")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	f := strings.Fields(string(out))
	if len(f) != 2 || f[0] != f[1] {
		t.Fatalf("child soft limit and the PAM one: %q", out)
	}
	if _, err := strconv.Atoi(f[0]); err != nil {
		t.Fatalf("output %q", out)
	}
}

// A limit PAM left alone gives the child the soft limit this process
// started with, not the one Go raised for itself.
func TestKeepPAMFileLimitLeavesAnUnchangedLimit(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	want, err := exec.Command("/bin/sh", "-c", "ulimit -n").Output()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), fileLimitTestStage+"=unchanged")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if strings.TrimSpace(string(out)) != strings.TrimSpace(string(want)) {
		t.Fatalf("child soft limit %q, want the original %q", out, want)
	}
}

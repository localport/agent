//go:build cgo && ((pam && linux) || darwin)

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

// runFileLimitStage does what the helper does before and during PAM:
// restoreStartFileLimit, then (stage "lower" or "raised") a limit set behind
// the syscall package's back, as pam_limits sets it from C: 200, or the soft
// limit the Go runtime had raised itself to. It prints the soft limit a
// child sees, then the one set (or "start").
func runFileLimitStage() int {
	var raised syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &raised); err != nil {
		fmt.Println(err)
		return 1
	}
	if err := restoreStartFileLimit(); err != nil {
		fmt.Println(err)
		return 1
	}
	set := "start"
	switch os.Getenv(fileLimitTestStage) {
	case "lower", "raised":
		pamSet := raised
		if os.Getenv(fileLimitTestStage) == "lower" {
			pamSet.Cur = 200
		}
		if err := setNofileBehindGo(&pamSet); err != nil {
			fmt.Println(err)
			return 1
		}
		set = strconv.FormatUint(pamSet.Cur, 10)
	}
	out, err := exec.Command("/bin/sh", "-c", "ulimit -n").Output()
	if err != nil {
		fmt.Println(err)
		return 1
	}
	fmt.Println(strings.TrimSpace(string(out)), set)
	return 0
}

func fileLimitStage(t *testing.T, stage string) (child, set string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), fileLimitTestStage+"="+stage)
	out, err := cmd.CombinedOutput()
	f := strings.Fields(string(out))
	if err != nil || len(f) != 2 {
		t.Fatalf("%v: %q", err, out)
	}
	return f[0], f[1]
}

// The soft open file limit PAM sets reaches the child, a lower one and one
// equal to the soft limit the Go runtime raised itself to alike.
func TestPAMFileLimitReachesTheChild(t *testing.T) {
	for _, stage := range []string{"lower", "raised"} {
		if child, set := fileLimitStage(t, stage); child != set {
			t.Errorf("%s: the child sees %s, PAM set %s", stage, child, set)
		}
	}
}

// Without a PAM limit the child gets the limit this process started with,
// not the one Go raised for itself.
func TestPAMFileLimitDefaultsToTheStartLimit(t *testing.T) {
	want, err := exec.Command("/bin/sh", "-c", "ulimit -n").Output()
	if err != nil {
		t.Fatal(err)
	}
	if child, _ := fileLimitStage(t, "start"); child != strings.TrimSpace(string(want)) {
		t.Fatalf("the child sees %s, want the start limit %s", child, want)
	}
}

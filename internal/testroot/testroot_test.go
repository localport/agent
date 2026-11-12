package testroot

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The probe test runs in a child so its skip or failure is observed, not
// taken by this test.
func TestRequire(t *testing.T) {
	if os.Getenv("LOCALPORT_TESTROOT_PROBE") == "1" {
		Require(t, "probe precondition")
		return
	}
	for _, tc := range []struct {
		env  string
		want string
	}{
		{"", "--- SKIP"},
		{"1", "--- FAIL"},
	} {
		cmd := exec.Command(os.Args[0], "-test.run", "^TestRequire$", "-test.v")
		cmd.Env = append(os.Environ(), "LOCALPORT_TESTROOT_PROBE=1", RequireEnv+"="+tc.env)
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), tc.want) || !strings.Contains(string(out), "probe precondition") {
			t.Errorf("%s=%q: want %s, got\n%s", RequireEnv, tc.env, tc.want, out)
		}
	}
}

//go:build cgo && linux

package sessionhelper

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/testroot"
)

// The open file limit pam_limits sets for the login reaches its shell.
// LOCALPORT_TEST_NOFILE is the soft limit /etc/security/limits.conf gives
// LOCALPORT_TEST_LOGIN; CI writes both.
func TestRootHelperKeepsThePAMFileLimit(t *testing.T) {
	login := rootLogin(t)
	want := os.Getenv("LOCALPORT_TEST_NOFILE")
	if !pamAvailable || want == "" {
		testroot.Require(t, "a PAM build and LOCALPORT_TEST_NOFILE, the login's limits.conf nofile soft limit")
	}
	out, _ := runRootTerminal(t, launcher.HelperRequest{Kind: launcher.KindTerminal, Login: login, Cols: 80, Rows: 24, Term: "xterm"},
		"echo NOFILE=$(ulimit -n) END; exit 0\n")
	if !strings.Contains(out, "NOFILE="+want+" END") {
		t.Fatalf("output %q: want the soft limit %s", out, want)
	}
}

// The utmp record of a session names the client's IP as its host (glibc;
// musl keeps no utmp).
func TestRootHelperUtmpHost(t *testing.T) {
	login := rootLogin(t)
	if _, err := os.Stat("/var/run/utmp"); err != nil {
		testroot.Require(t, "a host with /var/run/utmp")
	}
	out, _ := runRootTerminal(t, launcher.HelperRequest{Kind: launcher.KindTerminal, Login: login, Cols: 80, Rows: 24, Term: "xterm", ClientAddr: "203.0.113.9:40022"},
		"echo WHO=$(who -m) END; exit 0\n")
	if !regexp.MustCompile(`WHO=\S+ .*\(203\.0\.113\.9\) END`).MatchString(out) {
		t.Fatalf("output %q: want the utmp host 203.0.113.9", out)
	}
}

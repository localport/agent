//go:build cgo && linux

package sessionhelper

import (
	"os"
	"os/exec"
	"path/filepath"
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

// The helper closes the session's utmp record when the session ends: once
// it exited, who no longer lists the session's terminal line.
func TestRootHelperClosesUtmpAtTheEnd(t *testing.T) {
	login := rootLogin(t)
	if _, err := os.Stat("/var/run/utmp"); err != nil {
		testroot.Require(t, "a host with /var/run/utmp")
	}
	// runRootTerminal returns after the helper exited.
	out, _ := runRootTerminal(t, launcher.HelperRequest{Kind: launcher.KindTerminal, Login: login, Cols: 80, Rows: 24, Term: "xterm"},
		"echo LINE=$(who -m | awk '{print $2}') END; exit 0\n")
	m := regexp.MustCompile(`LINE=(\S+) END`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("output %q: no utmp line for the session", out)
	}
	// A file argument: without one, GNU who hides records whose pid is dead,
	// which would hide an unclosed record of the exited shell too. A copy,
	// because a gnulib build with systemd reads logind sessions instead when
	// the argument equals UTMP_FILE, and where /var/run is a real directory
	// no other path names that file.
	records, err := os.ReadFile("/var/run/utmp")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "utmp")
	if err := os.WriteFile(file, records, 0o600); err != nil {
		t.Fatal(err)
	}
	who, err := exec.Command("who", file).Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(who), "\n") {
		if f := strings.Fields(l); len(f) > 1 && f[1] == m[1] {
			t.Fatalf("who lists %s after the session ended: %q", m[1], l)
		}
	}
}

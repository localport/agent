//go:build linux

package session

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"testing"

	"github.com/localport/agent/internal/security"
)

// rootTestUser creates an unprivileged account with a home and /bin/sh and
// returns its record from the agent's lookup.
func rootTestUser(t *testing.T) *userRecord {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (make test-root)")
	}
	const name = "lproottest"
	_ = exec.Command("userdel", "-r", name).Run()
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/sh", name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("userdel", "-r", name).Run() })
	u, err := lookupUser(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// rootSession opens a terminal session as user over host with the agent
// running as root.
func rootSession(t *testing.T, host *terminalHost, user *userRecord) (*testClient, *eventLog) {
	t.Helper()
	ts, events := terminalServer(t, host, true, "")
	ts.users = lookupUser
	ts.cfg.Logins = append(ts.cfg.Logins, user.Name)
	return ts.openStart(t, ts.ticket(t, func(p *Ticket) { p.Login = user.Name }), []byte(terminalStartBody)), events
}

// The primary path runs the host's login(1) -f as root: the shell runs as
// the login. Input is sent at the shell's prompt: login(1) flushes the
// terminal's input while it sets the terminal up.
func TestRootTerminalLogin(t *testing.T) {
	user := rootTestUser(t)
	host := &terminalHost{
		logins:         systemTerminalHost.logins,
		selinuxEnforce: noLoginHost(t).selinuxEnforce,
		checkLogin:     security.CheckServiceBinary,
	}
	if _, err := host.selectLogin(); err != nil {
		t.Skipf("no usable login(1): %v", err)
	}
	c, _ := rootSession(t, host, user)
	c.readUntil(t, regexp.MustCompile(`\$ $`))
	c.send(t, TypeData, "echo ID=$(id -u)-END; exit\n")
	if got := c.readUntil(t, regexp.MustCompile(`ID=(\d+)-END`)); got != strconv.FormatUint(uint64(user.UID), 10) {
		t.Fatalf("id -u %s, want %d", got, user.UID)
	}
	// util-linux login(1) exits 0 after the shell ends.
	c.expectExit(t, 0)
}

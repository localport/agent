//go:build !windows

package service

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/localport/agent/internal/errcode"
)

// linuxDatabases writes passwd, shadow, group and login.defs for the agent
// account into a temp directory and points the shape check at them.
func linuxDatabases(t *testing.T, passwd, shadow, group, loginDefs string) {
	// loginDefs "" leaves login.defs missing.
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if content != "" {
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return p
	}
	prev := [4]string{passwdPath, shadowPath, groupPath, loginDefsPath}
	t.Cleanup(func() { passwdPath, shadowPath, groupPath, loginDefsPath = prev[0], prev[1], prev[2], prev[3] })
	passwdPath, shadowPath = write("passwd", passwd), write("shadow", shadow)
	groupPath, loginDefsPath = write("group", group), write("login.defs", loginDefs)
}

// The databases of a safe account, named AgentAccount as on the build OS.
var (
	safePasswd = "root:x:0:0:root:/root:/bin/bash\n" + AgentAccount + ":x:998:997:Localport agent:/nonexistent:/usr/sbin/nologin\n"
	safeShadow = "root:$6$abc:19000::::::\n" + AgentAccount + ":!*:19000::::::\n"
	safeGroup  = "root:x:0:\nsudo:x:27:alice\n" + AgentAccount + ":x:997:\n"
)

// The shape useradd --system and systemd-sysusers create passes, and the one
// OpenWrt's user_add creates: shadow hash "x", shell /bin/false, uid 32768
// and no login.defs.
func TestLinuxAccountShapeAcceptsASystemAccount(t *testing.T) {
	linuxDatabases(t, safePasswd, safeShadow, safeGroup, "SYS_UID_MAX 999\n")
	if err := linuxAccountShape(Account{UID: 998, GID: 997}); err != nil {
		t.Fatalf("a system account = %v, want accepted", err)
	}
	openwrt := AgentAccount + ":x:32768:32768:" + AgentAccount + ":/var/run/" + AgentAccount + ":/bin/false\n"
	linuxDatabases(t, openwrt, AgentAccount+":x:0:0:99999:7:::\n", AgentAccount+":x:32768:\n", "")
	if err := linuxAccountShape(Account{UID: 32768, GID: 32768}); err != nil {
		t.Fatalf("an OpenWrt account = %v, want accepted", err)
	}
}

// Each way the account could log in or reach more than it needs is named.
func TestLinuxAccountShapeRefusesAnUnsafeAccount(t *testing.T) {
	home := t.TempDir()
	for _, c := range []struct {
		name, passwd, shadow, group, defs string
		acct                              Account
		want                              string
	}{
		{"password hash", safePasswd, strings.Replace(safeShadow, AgentAccount+":!*", AgentAccount+":$6$x", 1), safeGroup, "", Account{UID: 998, GID: 997}, "password is not locked"},
		{"empty password", safePasswd, strings.Replace(safeShadow, AgentAccount+":!*", AgentAccount+":", 1), safeGroup, "", Account{UID: 998, GID: 997}, "password is not locked"},
		{"password in passwd", strings.Replace(safePasswd, AgentAccount+":x:", AgentAccount+"::", 1), safeShadow, safeGroup, "", Account{UID: 998, GID: 997}, "password is not locked"},
		{"login shell", strings.Replace(safePasswd, "/usr/sbin/nologin", "/bin/sh", 1), safeShadow, safeGroup, "", Account{UID: 998, GID: 997}, "shell /bin/sh allows a login"},
		{"primary group", safePasswd, safeShadow, safeGroup, "", Account{UID: 998, GID: 27}, "primary group is not " + AgentAccount},
		{"user uid", safePasswd, safeShadow, safeGroup, "# no SYS_UID_MAX\n", Account{UID: 1001, GID: 997}, "outside the system range 1-999"},
		{"uid 0", safePasswd, safeShadow, safeGroup, "", Account{UID: 0, GID: 997}, "root's"},
		{"DES hash", safePasswd, strings.Replace(safeShadow, AgentAccount+":!*", AgentAccount+":abCDefGHijKLm", 1), safeGroup, "", Account{UID: 998, GID: 997}, "password is not locked"},
		{"login.defs range", safePasswd, safeShadow, safeGroup, "SYS_UID_MAX 499\n", Account{UID: 998, GID: 997}, "outside the system range 1-499"},
		{"sudo member", safePasswd, safeShadow, strings.Replace(safeGroup, "sudo:x:27:alice", "sudo:x:27:alice,"+AgentAccount, 1), "", Account{UID: 998, GID: 997}, "member of sudo"},
		{"own home", strings.Replace(safePasswd, "/nonexistent", home, 1), safeShadow, safeGroup, "", Account{UID: os.Getuid(), GID: 997}, "is writable by it"},
	} {
		t.Run(c.name, func(t *testing.T) {
			linuxDatabases(t, c.passwd, c.shadow, c.group, c.defs)
			err := linuxAccountShape(c.acct)
			if !errors.Is(err, errcode.New(errcode.AgentAccountUnsafe)) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("linuxAccountShape = %v, want AG147 naming %q", err, c.want)
			}
		})
	}
}

// A shadow the caller may not read leaves only the password unchecked: the
// other rules still decide, and a pass is ErrPasswordUnchecked. With no shadow
// database at all, the passwd "x" is the hash and the account is locked.
func TestLinuxAccountShapeWithoutTheShadow(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode 000 file")
	}
	linuxDatabases(t, safePasswd, safeShadow, safeGroup, "")
	if err := os.Chmod(shadowPath, 0); err != nil {
		t.Fatal(err)
	}
	if err := linuxAccountShape(Account{UID: 998, GID: 997}); !errors.Is(err, ErrPasswordUnchecked) {
		t.Fatalf("unreadable shadow = %v, want ErrPasswordUnchecked", err)
	}
	if err := linuxAccountShape(Account{UID: 0, GID: 997}); !errors.Is(err, errcode.New(errcode.AgentAccountUnsafe)) {
		t.Fatalf("unreadable shadow, uid 0 = %v, want AG147", err)
	}
	linuxDatabases(t, safePasswd, "", safeGroup, "")
	if err := linuxAccountShape(Account{UID: 998, GID: 997}); err != nil {
		t.Fatalf("no shadow database = %v, want accepted", err)
	}
}

// An account whose group has no entry has the wrong primary group (AG147).
func TestLinuxAccountShapeWithoutTheGroup(t *testing.T) {
	linuxDatabases(t, safePasswd, safeShadow, "root:x:0:\n", "")
	err := linuxAccountShape(Account{UID: 998, GID: 997})
	if !errors.Is(err, errcode.New(errcode.AgentAccountUnsafe)) || !strings.Contains(err.Error(), "primary group") {
		t.Fatalf("no group entry = %v, want AG147 naming the primary group", err)
	}
}

package service

import (
	"context"
	"errors"
	"slices"
	"testing"
)

type fakeAccounts struct {
	uid, gid int
	found    bool
	err      error
}

func (f *fakeAccounts) lookup(string) (int, int, bool, error) { return f.uid, f.gid, f.found, f.err }

func TestEnsureAccountCreatesOnlyWhenMissing(t *testing.T) {
	db := &fakeAccounts{uid: 990, gid: 990, found: true}
	created := false
	run := func(context.Context, string, ...string) (string, error) { created = true; return "", nil }
	acct, err := ensureAccount(context.Background(), run, db)
	if err != nil || acct != (Account{UID: 990, GID: 990}) || created {
		t.Fatalf("existing account: %v, %v, created %v", acct, err, created)
	}

	db.err = errors.New("nss down")
	if _, err := ensureAccount(context.Background(), run, db); err == nil {
		t.Fatal("a lookup failure was ignored")
	}
}

func TestAccountTool(t *testing.T) {
	has := func(paths ...string) func(string) bool {
		return func(p string) bool { return slices.Contains(paths, p) }
	}
	if tool, shadow := accountTool(has("/usr/sbin/useradd", "/usr/sbin/adduser")); tool != "/usr/sbin/useradd" || !shadow {
		t.Errorf("shadow host: %q, %v", tool, shadow)
	}
	if tool, shadow := accountTool(has("/usr/sbin/adduser")); tool != "/usr/sbin/adduser" || shadow {
		t.Errorf("BusyBox host: %q, %v", tool, shadow)
	}
	if tool, _ := accountTool(has()); tool != "" {
		t.Errorf("no tool: %q", tool)
	}
	if got := nologin(has("/sbin/nologin")); got != "/sbin/nologin" {
		t.Errorf("nologin = %q", got)
	}
	if got := nologin(has()); got != "/bin/false" {
		t.Errorf("nologin fallback = %q", got)
	}
}

func TestCommandsFor(t *testing.T) {
	group, usr := commandsFor("/usr/sbin/useradd", true, false, "/usr/sbin/nologin")
	if !slices.Equal(group, []string{"/usr/sbin/groupadd", "--system", "localport"}) {
		t.Errorf("groupadd = %q", group)
	}
	if !slices.Equal(usr, []string{"/usr/sbin/useradd", "--system", "--gid", "localport", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "--comment", accountDescription, "localport"}) {
		t.Errorf("useradd = %q", usr)
	}
	group, usr = commandsFor("/usr/sbin/adduser", false, true, "/sbin/nologin")
	if group != nil {
		t.Errorf("addgroup ran for an existing group: %q", group)
	}
	if !slices.Equal(usr, []string{"/usr/sbin/adduser", "-S", "-D", "-H", "-h", "/var/empty", "-s", "/sbin/nologin", "-G", "localport", "-g", accountDescription, "localport"}) {
		t.Errorf("adduser = %q", usr)
	}
}

func TestDeleteCommandsFor(t *testing.T) {
	usr, group := deleteCommandsFor("/usr/sbin/useradd", true)
	if !slices.Equal(usr, []string{"/usr/sbin/userdel", "localport"}) || !slices.Equal(group, []string{"/usr/sbin/groupdel", "localport"}) {
		t.Errorf("shadow: %q, %q", usr, group)
	}
	usr, group = deleteCommandsFor("/usr/sbin/adduser", false)
	if !slices.Equal(usr, []string{"/usr/sbin/deluser", "localport"}) || !slices.Equal(group, []string{"/usr/sbin/delgroup", "localport"}) {
		t.Errorf("BusyBox: %q, %q", usr, group)
	}
}

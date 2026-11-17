package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/localport/agent/internal/errcode"
)

type fakeAccounts struct {
	uid, gid int
	found    bool
	err      error
}

func (f *fakeAccounts) lookup(string) (int, int, bool, error) { return f.uid, f.gid, f.found, f.err }

// skipShapeCheck makes ensureAccount accept any account until the test ends;
// the shape check has tests of its own (account_darwin_test.go).
func skipShapeCheck(t *testing.T) {
	prev := checkShape
	checkShape = func(context.Context, runner, Account) error { return nil }
	t.Cleanup(func() { checkShape = prev })
}

func TestEnsureAccountCreatesOnlyWhenMissing(t *testing.T) {
	skipShapeCheck(t)
	db := &fakeAccounts{uid: 990, gid: 990, found: true}
	created := false
	run := func(context.Context, string, ...string) (string, error) { created = true; return "", nil }
	acct, err := ensureAccount(context.Background(), run, db, "")
	if err != nil || acct != (Account{UID: 990, GID: 990}) || created {
		t.Fatalf("existing account: %v, %v, created %v", acct, err, created)
	}

	db.err = errors.New("nss down")
	if _, err := ensureAccount(context.Background(), run, db, ""); err == nil {
		t.Fatal("a lookup failure was ignored")
	}
}

// ensureAccount refuses the account the shape check refuses, whether it
// found the account or created it, and returns no ids with the refusal.
func TestEnsureAccountRunsTheShapeCheck(t *testing.T) {
	unsafe := errcode.New(errcode.AgentAccountUnsafe).With(nil, "it is a member of staff")
	prev := checkShape
	var checked []Account
	checkShape = func(_ context.Context, _ runner, acct Account) error { checked = append(checked, acct); return unsafe }
	t.Cleanup(func() { checkShape = prev })
	run := func(context.Context, string, ...string) (string, error) { return "", nil }
	for name, db := range map[string]accounts{
		"found":   &fakeAccounts{uid: 460, gid: 460, found: true},
		"created": &seqAccounts{found: []bool{false, true}},
	} {
		checked = nil
		acct, err := ensureAccount(context.Background(), run, db, "")
		if !errors.Is(err, unsafe) || acct != (Account{}) || len(checked) != 1 {
			t.Errorf("%s: ensureAccount = %v, %v after %d checks, want the AG147 refusal after one", name, acct, err, len(checked))
		}
	}
}

// seqAccounts answers each lookup from found in turn, the last one repeated.
type seqAccounts struct{ found []bool }

func (s *seqAccounts) lookup(string) (int, int, bool, error) {
	f := s.found[0]
	if len(s.found) > 1 {
		s.found = s.found[1:]
	}
	return 990, 990, f, nil
}

// A create that fails because a concurrent installer created the account
// first returns that account; a create failure with the account still
// missing is the create's error.
func TestEnsureAccountAfterAConcurrentCreate(t *testing.T) {
	skipShapeCheck(t)
	exists := errors.New("the user already exists")
	run := func(context.Context, string, ...string) (string, error) { return "", exists }
	acct, err := ensureAccount(context.Background(), run, &seqAccounts{found: []bool{false, true}}, "")
	if err != nil || acct != (Account{UID: 990, GID: 990}) {
		t.Fatalf("raced create = %v, %v, want the account the other installer created", acct, err)
	}
	if _, err := ensureAccount(context.Background(), run, &seqAccounts{found: []bool{false}}, ""); err == nil {
		t.Fatal("a failed create with no account was accepted")
	}
}

// The packages' sysusers.d line and postinstall fallback define the account
// createAccount creates on Linux: same name, description, home and nologin
// shell.
func TestPackagedAccountMatchesCreateAccount(t *testing.T) {
	const linuxAccount = "localport"
	if runtime.GOOS == "linux" && AgentAccount != linuxAccount {
		t.Fatalf("AgentAccount = %q on Linux, want %q", AgentAccount, linuxAccount)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "packaging", "nfpm", "sysusers.conf"))
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("u %s - %q %s -", linuxAccount, accountDescription, accountHome)
	var got []string
	for line := range strings.SplitSeq(string(raw), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			got = append(got, strings.Join(strings.Fields(line), " "))
		}
	}
	if !slices.Equal(got, []string{want}) {
		t.Fatalf("sysusers.conf directives = %q, want [%q]", got, want)
	}
	post, err := os.ReadFile(filepath.Join("..", "..", "packaging", "nfpm", "postinstall.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fallback := range []string{
		"--home-dir " + accountHome + ` \`,
		`--comment "` + accountDescription + `" "$name"`,
		"-h " + accountHome + ` -s "$nologin"`,
		`-g "` + accountDescription + `" "$name"`,
	} {
		if !strings.Contains(string(post), fallback) {
			t.Errorf("postinstall.sh lacks %q", fallback)
		}
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
	if !slices.Equal(group, []string{"/usr/sbin/groupadd", "--system", AgentAccount}) {
		t.Errorf("groupadd = %q", group)
	}
	if !slices.Equal(usr, []string{"/usr/sbin/useradd", "--system", "--gid", AgentAccount, "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "--comment", accountDescription, AgentAccount}) {
		t.Errorf("useradd = %q", usr)
	}
	group, usr = commandsFor("/usr/sbin/adduser", false, true, "/sbin/nologin")
	if group != nil {
		t.Errorf("addgroup ran for an existing group: %q", group)
	}
	if !slices.Equal(usr, []string{"/usr/sbin/adduser", "-S", "-D", "-H", "-h", "/nonexistent", "-s", "/sbin/nologin", "-G", AgentAccount, "-g", accountDescription, AgentAccount}) {
		t.Errorf("adduser = %q", usr)
	}
}

func TestDeleteCommandsFor(t *testing.T) {
	usr, group := deleteCommandsFor("/usr/sbin/useradd", true)
	if !slices.Equal(usr, []string{"/usr/sbin/userdel", AgentAccount}) || !slices.Equal(group, []string{"/usr/sbin/groupdel", AgentAccount}) {
		t.Errorf("shadow: %q, %q", usr, group)
	}
	usr, group = deleteCommandsFor("/usr/sbin/adduser", false)
	if !slices.Equal(usr, []string{"/usr/sbin/deluser", AgentAccount}) || !slices.Equal(group, []string{"/usr/sbin/delgroup", AgentAccount}) {
		t.Errorf("BusyBox: %q, %q", usr, group)
	}
}

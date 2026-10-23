package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A lookup still blocked in libc after its deadline refuses every later
// lookup until it returns.
func TestDirectoryLookupAllowsOneInFlight(t *testing.T) {
	release := make(chan struct{})
	d := &directoryLookup{resolve: func(login string) (*userRecord, error) {
		<-release
		return testUser(login, 501), nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := d.lookup(ctx, "pi"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked lookup: %v, want the deadline", err)
	}
	if _, err := d.lookup(context.Background(), "pi"); !errors.Is(err, errLookupPending) {
		t.Fatalf("lookup while one is pending: %v, want errLookupPending", err)
	}
	close(release)
	for end := time.Now().Add(5 * time.Second); ; {
		u, err := d.lookup(context.Background(), "pi")
		if err == nil && u.UID == 501 {
			return
		}
		if !errors.Is(err, errLookupPending) || time.Now().After(end) {
			t.Fatalf("lookup after the release: %v, %v", u, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestDirectoryLookupStartsNothingAfterTheDeadline(t *testing.T) {
	d := &directoryLookup{resolve: func(string) (*userRecord, error) {
		t.Error("resolve ran after the deadline")
		return nil, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.lookup(ctx, "pi"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v, want the context's", err)
	}
}

func TestResolveDirectoryUser(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	u, err := resolveDirectoryUser(me.Username)
	if err != nil {
		t.Fatal(err)
	}
	if int(u.UID) != os.Getuid() || len(u.Groups) == 0 || u.Groups[0] != u.GID || u.Home != me.HomeDir {
		t.Fatalf("got %+v for %s", *u, me.Username)
	}
	if _, err := resolveDirectoryUser("lp-no-such-user"); !errors.Is(err, errNoUser) {
		t.Fatalf("unknown login: %v, want errNoUser", err)
	}
}

func TestParseUserShell(t *testing.T) {
	for out, want := range map[string]string{
		"UserShell: /bin/zsh\n":             "/bin/zsh",
		"UserShell: /bin/zsh":               "/bin/zsh",
		"No such key: UserShell\n":          "",
		"UserShell:\n /bin/zsh\n":           "",
		"UserShell: zsh\n":                  "",
		"UserShell: /bin/zsh /bin/bash\n":   "",
		"UserShell: /bin/../bin/zsh\n":      "",
		"UserShell: /bin/zsh\nUserShell: x": "",
		"":                                  "",
	} {
		if got := parseUserShell([]byte(out)); got != want {
			t.Errorf("parseUserShell(%q) = %q, want %q", out, got, want)
		}
	}
}

// fakeDscl writes a dscl that records its argv and environment, prints out
// and exits with status.
func fakeDscl(t *testing.T, out string, status int) (tool, dir string) {
	t.Helper()
	dir = t.TempDir()
	tool = filepath.Join(dir, "dscl")
	script := fmt.Sprintf("#!/bin/sh\necho \"$*\" > %s/args\nenv > %s/env\nprintf '%%s' '%s'\nexit %d\n", dir, dir, out, status)
	if err := os.WriteFile(tool, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return tool, dir
}

func TestLoginShell(t *testing.T) {
	t.Setenv("LOCALPORT_LOOKUP_SENTINEL", "agent")
	tool, dir := fakeDscl(t, "UserShell: /bin/zsh\n", 0)
	shell, err := loginShell(context.Background(), tool, "pi")
	if err != nil || shell != "/bin/zsh" {
		t.Fatalf("loginShell = %q, %v", shell, err)
	}
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	env, _ := os.ReadFile(filepath.Join(dir, "env"))
	if string(args) != "/Search -read /Users/pi UserShell\n" || strings.Contains(string(env), "LOCALPORT_LOOKUP_SENTINEL") {
		t.Fatalf("dscl ran with args %q and env %q", args, env)
	}

	tool, _ = fakeDscl(t, "No such key: UserShell\n", 0)
	if shell, err := loginShell(context.Background(), tool, "pi"); err != nil || shell != "" {
		t.Fatalf("no value: %q, %v; want the default", shell, err)
	}
	tool, _ = fakeDscl(t, "", 56)
	if _, err := loginShell(context.Background(), tool, "pi"); err == nil {
		t.Fatal("a failed dscl returned no error")
	}
	tool, _ = fakeDscl(t, "", 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := loginShell(ctx, tool, "pi"); !errors.Is(err, context.Canceled) {
		t.Fatalf("after the deadline: %v", err)
	}
}

// The shell lookup runs in the lookup's in-flight slot, and its failure
// fails the lookup.
func TestDirectoryLookupReadsTheShell(t *testing.T) {
	d := &directoryLookup{
		resolve: func(login string) (*userRecord, error) { return &userRecord{Name: login}, nil },
		shell:   func(context.Context, string) (string, error) { return "/bin/zsh", nil },
	}
	if u, err := d.lookup(context.Background(), "pi"); err != nil || u.Shell != "/bin/zsh" {
		t.Fatalf("lookup = %+v, %v", u, err)
	}
	d.shell = func(context.Context, string) (string, error) { return "", errors.New("dscl exited with status 56") }
	if u, err := d.lookup(context.Background(), "pi"); err == nil {
		t.Fatalf("lookup = %+v with a failed shell lookup", u)
	}
}

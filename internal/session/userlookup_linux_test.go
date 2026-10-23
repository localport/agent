package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// getentAnswer is what the fake getent prints and exits with for one
// argument list; script, when set, replaces both.
type getentAnswer struct {
	out    string
	status int
	script string
}

// fakeGetent writes a getent script answering by its arguments (any other
// list exits 2) and returns a lookup that runs it, plus the directory where
// the script records its environment and working directory.
func fakeGetent(t *testing.T, answers map[string]getentAnswer) (*getentLookup, string) {
	t.Helper()
	dir := t.TempDir()
	var script strings.Builder
	fmt.Fprintf(&script, "#!/bin/sh\nenv > %s/env\npwd > %s/cwd\necho \"$*\" >> %s/calls\ncase \"$*\" in\n", dir, dir, dir)
	i := 0
	for args, a := range answers {
		body := a.script
		if body == "" {
			out := filepath.Join(dir, fmt.Sprintf("out%d", i))
			if err := os.WriteFile(out, []byte(a.out), 0o600); err != nil {
				t.Fatal(err)
			}
			body = fmt.Sprintf("cat %s; exit %d", out, a.status)
		}
		fmt.Fprintf(&script, "'%s') %s;;\n", args, body)
		i++
	}
	script.WriteString("*) exit 2;;\nesac\n")
	path := filepath.Join(dir, "getent")
	if err := os.WriteFile(path, []byte(script.String()), 0o700); err != nil {
		t.Fatal(err)
	}
	return &getentLookup{getent: []string{filepath.Join(dir, "missing"), path}}, dir
}

func lookupCtx(t *testing.T, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

const piPasswd = "pi:x:1000:1000:Pi User:/home/pi:/bin/bash\n"

func TestGetentLookupResolves(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answers map[string]getentAnswer
		groups  []uint32
	}{
		{"initgroups", map[string]getentAnswer{
			"passwd pi":     {out: piPasswd},
			"initgroups pi": {out: "pi                    1000 27 100 27\n"},
		}, []uint32{1000, 27, 100}},
		{"initgroups without the primary group", map[string]getentAnswer{
			"passwd pi":     {out: piPasswd},
			"initgroups pi": {out: "pi 27\n"},
		}, []uint32{1000, 27}},
		{"initgroups unsupported filters the group database", map[string]getentAnswer{
			"passwd pi":     {out: piPasswd},
			"initgroups pi": {status: 1},
			"group":         {out: "root:x:0:\nsudo:x:27:bob,pi\nusers:x:100:bob\npi:x:1000:\npix:x:2000:pix\n"},
		}, []uint32{1000, 27}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("LOCALPORT_LOOKUP_SENTINEL", "leaked")
			g, dir := fakeGetent(t, tc.answers)
			u, err := g.lookup(lookupCtx(t, 5*time.Second), "pi")
			if err != nil {
				t.Fatal(err)
			}
			want := userRecord{Name: "pi", UID: 1000, GID: 1000, Groups: tc.groups, Home: "/home/pi", Shell: "/bin/bash"}
			if u.Name != want.Name || u.UID != want.UID || u.GID != want.GID || !slices.Equal(u.Groups, want.Groups) || u.Home != want.Home || u.Shell != want.Shell {
				t.Fatalf("got %+v, want %+v", *u, want)
			}
			env, _ := os.ReadFile(filepath.Join(dir, "env"))
			if strings.Contains(string(env), "LOCALPORT_LOOKUP_SENTINEL") || strings.Contains(string(env), os.Getenv("PATH")) {
				t.Fatalf("getent ran with the agent's environment:\n%s", env)
			}
			if cwd, _ := os.ReadFile(filepath.Join(dir, "cwd")); string(cwd) != "/\n" {
				t.Fatalf("getent ran in %q, want /", cwd)
			}
		})
	}
}

func TestGetentLookupRefuses(t *testing.T) {
	malformed := func(passwd string) map[string]getentAnswer {
		return map[string]getentAnswer{"passwd pi": {out: passwd}, "initgroups pi": {out: "pi 1000\n"}}
	}
	for _, tc := range []struct {
		name    string
		answers map[string]getentAnswer
		noUser  bool
		is      error
	}{
		{"no passwd entry", map[string]getentAnswer{"passwd pi": {status: 2}}, true, nil},
		{"no initgroups entry", map[string]getentAnswer{"passwd pi": {out: piPasswd}, "initgroups pi": {status: 2}}, true, nil},
		{"passwd failure", map[string]getentAnswer{"passwd pi": {status: 3}}, false, nil},
		{"initgroups failure", map[string]getentAnswer{"passwd pi": {out: piPasswd}, "initgroups pi": {status: 4}}, false, nil},
		{"group database failure", map[string]getentAnswer{"passwd pi": {out: piPasswd}, "initgroups pi": {status: 1}, "group": {status: 1}}, false, nil},
		{"six fields", malformed("pi:x:1000:1000:/home/pi:/bin/bash\n"), false, nil},
		{"eight fields", malformed("pi:x:1000:1000::/home/pi:/bin/bash:x\n"), false, nil},
		{"other name", malformed("pix:x:1000:1000::/home/pi:/bin/bash\n"), false, nil},
		{"non-numeric uid", malformed("pi:x:abc:1000::/home/pi:/bin/bash\n"), false, nil},
		{"uid past 32 bits", malformed("pi:x:4294967296:1000::/home/pi:/bin/bash\n"), false, nil},
		{"negative gid", malformed("pi:x:1000:-1::/home/pi:/bin/bash\n"), false, nil},
		{"two lines", malformed(piPasswd + piPasswd), false, nil},
		{"no final newline", malformed(strings.TrimSuffix(piPasswd, "\n")), false, nil},
		{"initgroups for another name", map[string]getentAnswer{"passwd pi": {out: piPasswd}, "initgroups pi": {out: "bob 1000\n"}}, false, nil},
		{"initgroups non-numeric gid", map[string]getentAnswer{"passwd pi": {out: piPasswd}, "initgroups pi": {out: "pi 1000 wheel\n"}}, false, nil},
		{"malformed group line", map[string]getentAnswer{"passwd pi": {out: piPasswd}, "initgroups pi": {status: 1}, "group": {out: "sudo:x:27\n"}}, false, nil},
		{"output past 64 KiB", map[string]getentAnswer{"passwd pi": {script: "head -c 70000 /dev/zero; exit 0"}}, false, errLookupOutputTooLarge},
		{"hung getent", map[string]getentAnswer{"passwd pi": {script: "exec sleep 10"}}, false, context.DeadlineExceeded},
		{"killed by a signal", map[string]getentAnswer{"passwd pi": {script: "kill -9 $$"}}, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := fakeGetent(t, tc.answers)
			start := time.Now()
			_, err := g.lookup(lookupCtx(t, 500*time.Millisecond), "pi")
			if took := time.Since(start); took > 2*time.Second {
				t.Fatalf("lookup took %v", took)
			}
			if err == nil {
				t.Fatal("lookup succeeded")
			}
			if errors.Is(err, errNoUser) != tc.noUser {
				t.Fatalf("err %v; errNoUser %v, want %v", err, errors.Is(err, errNoUser), tc.noUser)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("err %v, want %v", err, tc.is)
			}
		})
	}
}

// A lookup whose deadline has passed starts no getent run.
func TestGetentLookupStartsNothingAfterTheDeadline(t *testing.T) {
	g, dir := fakeGetent(t, map[string]getentAnswer{"passwd pi": {out: piPasswd}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := g.lookup(ctx, "pi"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v, want the context's", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "calls")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("getent ran after the deadline: %v", err)
	}
}

// Without getent the account files are parsed.
func TestGetentLookupFallsBackToTheAccountFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	g := &getentLookup{
		getent: []string{filepath.Join(dir, "no-getent")},
		passwd: write("passwd", "root:x:0:0:root:/root:/bin/ash\n\n"+piPasswd),
		group:  write("group", "root:x:0:root\nwheel:x:10:root,pi\npi:x:1000:\n"),
	}
	u, err := g.lookup(lookupCtx(t, time.Second), "pi")
	if err != nil {
		t.Fatal(err)
	}
	if u.UID != 1000 || u.Home != "/home/pi" || u.Shell != "/bin/bash" || !slices.Equal(u.Groups, []uint32{1000, 10}) {
		t.Fatalf("got %+v", *u)
	}
	if _, err := g.lookup(lookupCtx(t, time.Second), "bob"); !errors.Is(err, errNoUser) {
		t.Fatalf("bob: %v, want errNoUser", err)
	}
	g.passwd = write("passwd-bad", piPasswd+"bob:x:1001\n")
	if _, err := g.lookup(lookupCtx(t, time.Second), "pi"); err == nil || errors.Is(err, errNoUser) {
		t.Fatalf("malformed passwd file: %v, want a failure", err)
	}
	g.passwd = filepath.Join(dir, "absent")
	if _, err := g.lookup(lookupCtx(t, time.Second), "pi"); err == nil || errors.Is(err, errNoUser) {
		t.Fatalf("absent passwd file: %v, want a failure", err)
	}
}

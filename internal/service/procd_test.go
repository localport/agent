package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func newProcd(t *testing.T, r *recorder) procd {
	dir := filepath.Join(t.TempDir(), "init.d")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return procd{initDir: dir, ubus: "ubus", run: r.run}
}

func TestProcdScripts(t *testing.T) {
	scripts, err := procdScripts(exe)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]string{
		ProcdService: {
			"#!/bin/sh /etc/rc.common",
			"# " + Marker,
			"USE_PROCD=1",
			"START=96",
			"\tprocd_set_param command " + exe + " run --service",
			"\tprocd_set_param user localport",
			"\tprocd_set_param group localport",
			"\tprocd_set_param no_new_privs 1",
			`	procd_set_param limits core="0 0"`,
			"\tprocd_set_param term_timeout 30",
			"\tprocd_send_signal " + ProcdService + " '*' HUP",
		},
		ProcdLauncherService: {
			"#!/bin/sh /etc/rc.common",
			"# " + Marker,
			"START=95",
			"\tprocd_set_param command /usr/local/bin/localport-session launcher",
			// An upgrade changes the binary's checksum, which makes start
			// restart the launcher.
			"\tprocd_set_param file /usr/local/bin/localport-session",
		},
	} {
		got := lines(scripts[name])
		for _, line := range want {
			if !slices.Contains(got, line) {
				t.Errorf("%s lacks the line %q", name, line)
			}
		}
	}
	if slices.Contains(lines(scripts[ProcdLauncherService]), "\tprocd_set_param user localport") {
		t.Error("launcher script runs as the agent account")
	}
	if _, err := procdScripts("/opt/$x/localport"); !errors.Is(err, ErrUnsafeExecutable) {
		t.Errorf("unsafe executable = %v, want ErrUnsafeExecutable", err)
	}
}

func TestProcdInstallSequence(t *testing.T) {
	r := &recorder{}
	p := newProcd(t, r)
	if err := p.Install(context.Background(), exe); err != nil {
		t.Fatal(err)
	}
	session, agent := p.script(ProcdLauncherService), p.script(ProcdService)
	want := []string{session + " enable", session + " start", agent + " enable", agent + " restart"}
	if !slices.Equal(r.calls, want) {
		t.Fatalf("commands = %q, want %q", r.calls, want)
	}
	r.calls = nil
	if err := p.Reload(context.Background()); err != nil || !slices.Equal(r.calls, []string{agent + " reload"}) {
		t.Fatalf("Reload = %v, commands %q", err, r.calls)
	}
	r.calls = nil
	if err := p.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	want = []string{agent + " stop", agent + " disable", session + " stop", session + " disable"}
	if !slices.Equal(r.calls, want) {
		t.Fatalf("uninstall commands = %q, want %q", r.calls, want)
	}
	for _, s := range p.paths() {
		if _, err := os.Stat(s); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s still there: %v", s, err)
		}
	}
}

func TestProcdMainPID(t *testing.T) {
	list := `ubus call service list {"name":"` + ProcdService + `"}`
	for _, c := range []struct {
		out  string
		want int
	}{
		{`{"localport-device":{"instances":{"instance1":{"running":true,"pid":4242,"command":["x"]}}}}`, 4242},
		{`{"localport-device":{"instances":{"instance1":{"running":false}}}}`, 0},
		{`{}`, 0},
	} {
		r := &recorder{out: map[string]string{list: c.out}}
		if pid, err := newProcd(t, r).MainPID(context.Background()); err != nil || pid != c.want {
			t.Errorf("MainPID for %s = %d, %v, want %d", c.out, pid, err, c.want)
		}
	}
	r := &recorder{out: map[string]string{list: "not json"}}
	if _, err := newProcd(t, r).MainPID(context.Background()); err == nil {
		t.Error("MainPID accepted output that is not JSON")
	}
}

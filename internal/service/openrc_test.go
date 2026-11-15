package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func newOpenRC(t *testing.T, r *recorder) openrc {
	dir := t.TempDir()
	return openrc{
		initDir:     filepath.Join(dir, "init.d"),
		runlevelDir: filepath.Join(dir, "runlevels"),
		rcService:   "rc-service",
		rcUpdate:    "rc-update",
		logDir:      filepath.Join(dir, "log"),
		account:     func() (Account, error) { return Account{UID: os.Getuid(), GID: os.Getgid()}, nil },
		run:         r.run,
	}
}

func TestOpenRCScripts(t *testing.T) {
	unixInitOnly(t)
	scripts, err := openrcScripts(exe)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]string{
		OpenRCService: {
			"#!/sbin/openrc-run",
			"# " + Marker,
			"supervisor=supervise-daemon",
			`command="` + exe + `"`,
			`command_args="run --service --log-file ` + openrcAgentLog + `"`,
			`command_user="localport:localport"`,
			"no_new_privs=yes",
			`rc_ulimit="-c 0"`,
			"respawn_max=0",
			`retry="TERM/30/KILL/5"`,
			`extra_started_commands="reload mainpid"`,
			"\tneed net " + OpenRCLauncherService,
			`	supervise-daemon "${RC_SVCNAME}" --signal HUP`,
			"\tservice_get_value child_pid",
		},
		OpenRCLauncherService: {
			"#!/sbin/openrc-run",
			"# " + Marker,
			"supervisor=supervise-daemon",
			`command="/usr/local/bin/localport-session"`,
			`command_args="launcher --log-file ` + openrcLauncherLog + `"`,
		},
	} {
		got := lines(scripts[name])
		for _, line := range want {
			if !slices.Contains(got, line) {
				t.Errorf("%s lacks the line %q", name, line)
			}
		}
	}
	// The launcher runs as root, and stopping it must not reach its sessions.
	for _, line := range lines(scripts[OpenRCLauncherService]) {
		for _, banned := range []string{"command_user=", "stopgroup=", "no_new_privs="} {
			if strings.HasPrefix(line, banned) {
				t.Errorf("launcher script sets %q", line)
			}
		}
	}
	if _, err := openrcScripts("/opt/a b/localport"); !errors.Is(err, ErrUnsafeExecutable) {
		t.Errorf("unsafe executable = %v, want ErrUnsafeExecutable", err)
	}
}

// linkRunlevel links name into runlevel as rc-update add does.
func linkRunlevel(t *testing.T, o openrc, runlevel, name string) {
	t.Helper()
	dir := filepath.Join(o.runlevelDir, runlevel)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(o.script(name), filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRCInstallSequence(t *testing.T) {
	unixInitOnly(t)
	r := &recorder{}
	o := newOpenRC(t, r)
	if err := os.Mkdir(o.initDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := o.Install(context.Background(), exe); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"rc-update add " + OpenRCLauncherService + " default",
		"rc-update add " + OpenRCService + " default",
		"rc-service " + OpenRCLauncherService + " restart",
		"rc-service " + OpenRCService + " restart",
	}
	if !slices.Equal(r.calls, want) {
		t.Fatalf("commands = %q, want %q", r.calls, want)
	}
	for _, p := range o.paths() {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o755 {
			t.Fatalf("%s mode = %v, %v, want 0755", p, fi, err)
		}
	}
	if fi, err := os.Lstat(o.logDir); err != nil || !fi.IsDir() {
		t.Fatalf("log dir = %v, %v", fi, err)
	}

	r.calls = nil
	if err := o.Reload(context.Background()); err != nil || !slices.Equal(r.calls, []string{"rc-service " + OpenRCService + " reload"}) {
		t.Fatalf("Reload = %v, commands %q", err, r.calls)
	}

	// rc-update del exits 1 alike for "not in that runlevel" and for a real
	// failure, so Uninstall deletes only where a runlevel links the service
	// and every del failure is an error.
	linkRunlevel(t, o, "default", OpenRCService)
	r.calls = nil
	failed := &CommandError{ExitCode: 1, Err: errors.New("exit status 1")}
	r.fail = map[string]error{"rc-update del " + OpenRCService + " default": failed}
	if err := o.Uninstall(context.Background()); !errors.Is(err, failed) {
		t.Fatalf("Uninstall with a failing del = %v, want the failure", err)
	}
	r.calls, r.fail = nil, nil
	if err := o.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	want = []string{
		"rc-service " + OpenRCService + " stop",
		"rc-update del " + OpenRCService + " default",
		"rc-service " + OpenRCLauncherService + " stop",
	}
	if !slices.Equal(r.calls, want) {
		t.Fatalf("uninstall commands = %q, want %q", r.calls, want)
	}
	for _, p := range o.paths() {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s still there: %v", p, err)
		}
	}
	if err := o.Uninstall(context.Background()); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("second Uninstall = %v, want ErrNotInstalled", err)
	}
}

func TestOpenRCMainPID(t *testing.T) {
	status := "rc-service " + OpenRCService + " status"
	mainpid := "rc-service " + OpenRCService + " mainpid"
	for _, c := range []struct {
		name      string
		statusErr error
		out       string
		want      int
	}{
		{name: "started", out: "4242\n", want: 4242},
		{name: "stopped", statusErr: &CommandError{ExitCode: 3, Err: errors.New("exit status 3")}, want: 0},
		{name: "crashed", statusErr: &CommandError{ExitCode: 32, Err: errors.New("exit status 32")}, want: 0},
		{name: "no child pid", out: "\n", want: 0},
	} {
		r := &recorder{fail: map[string]error{status: c.statusErr}, out: map[string]string{mainpid: c.out}}
		if pid, err := newOpenRC(t, r).MainPID(context.Background()); err != nil || pid != c.want {
			t.Errorf("%s: MainPID = %d, %v, want %d", c.name, pid, err, c.want)
		}
	}
	r := &recorder{fail: map[string]error{status: &CommandError{ExitCode: -1, Err: context.DeadlineExceeded}}}
	if _, err := newOpenRC(t, r).MainPID(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("status timeout: MainPID = %v, want the timeout", err)
	}
	// Exit 1 is rc-service's failure (an unknown service, eerrorx), not a
	// service state: an error, never "not running".
	failed := &CommandError{ExitCode: 1, Err: errors.New("exit status 1")}
	r = &recorder{fail: map[string]error{status: failed}}
	if _, err := newOpenRC(t, r).MainPID(context.Background()); !errors.Is(err, failed) {
		t.Errorf("status exit 1: MainPID = %v, want the failure", err)
	}
}

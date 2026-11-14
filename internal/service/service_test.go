package service

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/tunnel"
)

// recorder is a runner that records each command. It answers from next,
// one entry per call while any are left, then from fail and out.
type recorder struct {
	calls []string
	next  map[string][]error
	fail  map[string]error
	out   map[string]string
}

func (r *recorder) run(_ context.Context, name string, args ...string) (string, error) {
	call := strings.Join(append([]string{name}, args...), " ")
	r.calls = append(r.calls, call)
	if queued := r.next[call]; len(queued) > 0 {
		r.next[call] = queued[1:]
		return "", queued[0]
	}
	return r.out[call], r.fail[call]
}

const exe = "/usr/local/bin/localport"

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func lines(b []byte) []string { return strings.Split(string(b), "\n") }

func TestSystemdUnits(t *testing.T) {
	units, err := systemdUnits(exe)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]string{
		SystemdUnit: {
			"# " + Marker,
			"User=" + AgentAccount,
			"Group=" + AgentAccount,
			"ExecStart=" + exe + " run --service",
			"ExecReload=/bin/kill -HUP $MAINPID",
			"Restart=always",
			"LimitCORE=0",
			"NoNewPrivileges=yes",
			"CapabilityBoundingSet=",
			"ProtectSystem=strict",
			"ReadWritePaths=-/etc/localport-device/identity -/etc/localport-device/run.lock",
			"TimeoutStopSec=30",
			"ProtectHome=yes",
			"PrivateTmp=yes",
			"PrivateDevices=yes",
			"PrivateIPC=yes",
			"RemoveIPC=yes",
			"ProtectProc=invisible",
			"ProcSubset=pid",
			"RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK",
			"SystemCallFilter=@system-service",
			"SystemCallFilter=~@privileged @resources",
			"SystemCallArchitectures=native",
			"Wants=network-online.target " + SystemdLauncherSocket,
			"WantedBy=multi-user.target",
		},
		SystemdLauncherSocket: {
			"# " + Marker,
			"ListenStream=" + launcher.LinuxSocketPath,
			"SocketUser=root",
			"SocketGroup=" + AgentAccount,
			"SocketMode=0660",
			"WantedBy=sockets.target",
		},
		SystemdLauncherService: {
			"# " + Marker,
			"ExecStart=/usr/local/bin/localport-session launcher",
			"KillMode=process",
			"Requires=" + SystemdLauncherSocket,
		},
	} {
		got := lines(units[name])
		for _, line := range want {
			if !slices.Contains(got, line) {
				t.Errorf("%s lacks the line %q", name, line)
			}
		}
	}
	// Every session inherits the launcher's sandbox, so its unit sets none.
	for _, line := range lines(units[SystemdLauncherService]) {
		for _, banned := range []string{"User=", "ProtectSystem=", "ProtectHome=", "PrivateTmp=", "PrivateDevices=", "NoNewPrivileges=", "CapabilityBoundingSet=", "SystemCallFilter=", "RestrictAddressFamilies="} {
			if strings.HasPrefix(line, banned) {
				t.Errorf("launcher unit sets %q, which confines the sessions it starts", line)
			}
		}
	}
}

var updateGolden = flag.Bool("update", false, "rewrite testdata/localport-device.service")

// testdata/localport-device.service is the generated agent unit, which CI
// scores with systemd-analyze security.
func TestSystemdAgentUnitMatchesGolden(t *testing.T) {
	units, err := systemdUnits(exe)
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "localport-device.service")
	if *updateGolden {
		if err := os.WriteFile(golden, units[SystemdUnit], 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(units[SystemdUnit], want) {
		t.Fatalf("generated agent unit differs from %s; rerun with -update and review the diff", golden)
	}
}

// Every service manager waits longer than the agent's longest graceful stop
// before it kills the agent, and the launchd bootout wait outlasts that.
func TestStopBudgetCoversTheAgentStop(t *testing.T) {
	if StopBudget <= tunnel.StopBound {
		t.Fatalf("StopBudget %v does not exceed tunnel.StopBound %v", StopBudget, tunnel.StopBound)
	}
	if bootoutWait <= StopBudget {
		t.Fatalf("bootoutWait %v does not outlast StopBudget %v", bootoutWait, StopBudget)
	}
}

func TestSystemdUnitsRefuseUnsafeExecutable(t *testing.T) {
	for _, bad := range []string{"localport", "/opt/my tools/localport", "/opt/%h/localport", "/opt/$HOME/localport", "/opt/\"x\"/localport", "/opt/x\n/localport"} {
		if _, err := systemdUnits(bad); !errors.Is(err, ErrUnsafeExecutable) {
			t.Errorf("systemdUnits(%q) = %v, want ErrUnsafeExecutable", bad, err)
		}
	}
}

// The refusal shows the path and the characters each manager allows.
func TestUnsafeExecutableRefusalsNameThePath(t *testing.T) {
	const bad = "/opt/my tools/localport"
	for name, generate := range map[string]func(string) (map[string][]byte, error){"systemd": systemdUnits, "openrc": openrcScripts, "procd": procdScripts} {
		_, err := generate(bad)
		if text, _ := errcode.Render(err); !errors.Is(err, ErrUnsafeExecutable) || !strings.Contains(text, bad) || !strings.Contains(text, "._+@/-") {
			t.Errorf("%s: Render = %q, want the path and the allowed characters", name, text)
		}
	}
}

func newSystemd(t *testing.T, r *recorder) systemd {
	return systemd{unitPath: filepath.Join(t.TempDir(), SystemdUnit), systemctl: "systemctl", run: r.run}
}

func TestSystemdInstallSequence(t *testing.T) {
	r := &recorder{}
	s := newSystemd(t, r)
	if err := s.Install(context.Background(), exe); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"systemctl daemon-reload",
		"systemctl enable --now " + SystemdLauncherSocket,
		"systemctl try-restart " + SystemdLauncherService,
		"systemctl enable " + SystemdUnit,
		"systemctl restart " + SystemdUnit,
	}
	if !slices.Equal(r.calls, want) {
		t.Fatalf("commands = %q, want %q", r.calls, want)
	}
	for _, u := range s.units() {
		if fi, err := os.Stat(u.path); err != nil || fi.Mode().Perm() != 0o644 {
			t.Fatalf("%s mode = %v, %v, want 0644", u.name, fi, err)
		}
	}
	if installed, err := s.Installed(); err != nil || !installed {
		t.Fatalf("Installed = %v, %v after Install", installed, err)
	}

	// A repeat install overwrites its own files and restarts the agent.
	r.calls = nil
	if err := s.Install(context.Background(), "/usr/bin/localport"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readFile(t, s.unitPath), "ExecStart=/usr/bin/localport run") {
		t.Fatal("a repeat install did not rewrite the unit")
	}
	if !slices.Equal(r.calls, want) {
		t.Fatalf("repeat commands = %q, want %q", r.calls, want)
	}

	r.calls = nil
	if err := s.Reload(context.Background()); err != nil || !slices.Equal(r.calls, []string{"systemctl reload " + SystemdUnit}) {
		t.Fatalf("Reload = %v, commands %q", err, r.calls)
	}
}

func TestSystemdCommandFailureIsSurfaced(t *testing.T) {
	failure := &CommandError{Command: "systemctl enable " + SystemdUnit, ExitCode: 1, Err: errors.New("exit status 1")}
	r := &recorder{fail: map[string]error{"systemctl enable " + SystemdUnit: failure}}
	s := newSystemd(t, r)
	err := s.Install(context.Background(), exe)
	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) || cmdErr.ExitCode != 1 {
		t.Fatalf("Install = %v, want the enable CommandError", err)
	}
	if slices.Contains(r.calls, "systemctl restart "+SystemdUnit) {
		t.Fatal("Install went on after a failed command")
	}
}

// A foreign launcher unit stops the install before any unit is written.
func TestSystemdInstallRefusesAForeignLauncherUnitFirst(t *testing.T) {
	r := &recorder{}
	s := newSystemd(t, r)
	foreign := filepath.Join(filepath.Dir(s.unitPath), SystemdLauncherService)
	writeFile(t, foreign, "[Service]\nExecStart=/usr/bin/someone-else\n")
	if err := s.Install(context.Background(), exe); !errors.Is(err, ErrForeignUnit) {
		t.Fatalf("Install = %v, want ErrForeignUnit", err)
	}
	if _, err := os.Stat(s.unitPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the agent unit was written before the refusal: %v", err)
	}
	if len(r.calls) > 0 {
		t.Fatalf("commands ran: %q", r.calls)
	}
}

func newLaunchd(t *testing.T, r *recorder) launchd {
	dir := t.TempDir()
	return launchd{
		plistPath: filepath.Join(dir, LaunchdLabel+".plist"),
		logDir:    filepath.Join(dir, "log"),
		account:   func() (Account, error) { return Account{UID: os.Getuid(), GID: os.Getgid()}, nil },
		run:       r.run,
	}
}

// The marker guards a file localport did not write: install, check and
// uninstall refuse it, leave it unchanged and run no service command.
func TestForeignDefinitionIsRefused(t *testing.T) {
	// Each definition file of each manager in turn is the foreign one.
	for name, build := range map[string]func(*testing.T, *recorder, int) (Manager, string){
		"systemd": func(t *testing.T, r *recorder, i int) (Manager, string) {
			s := newSystemd(t, r)
			return s, s.paths()[i]
		},
		"launchd": func(t *testing.T, r *recorder, i int) (Manager, string) {
			l := newLaunchd(t, r)
			return l, l.plists()[i%2]
		},
	} {
		for i := range 3 {
			t.Run(fmt.Sprintf("%s/%d", name, i), func(t *testing.T) {
				r := &recorder{}
				m, path := build(t, r, i)
				const foreign = "[Service]\nExecStart=/usr/bin/someone-else\n"
				writeFile(t, path, foreign)

				if _, err := m.Check(); !errors.Is(err, ErrForeignUnit) {
					t.Errorf("Check = %v, want ErrForeignUnit", err)
				}
				// Installed judges the agent's definition only.
				_, err := m.Installed()
				if agent := filepath.Base(path) == SystemdUnit || filepath.Base(path) == LaunchdLabel+".plist"; agent != errors.Is(err, ErrForeignUnit) {
					t.Errorf("Installed = %v with %s foreign", err, filepath.Base(path))
				}
				if err := m.Install(context.Background(), exe); !errors.Is(err, ErrForeignUnit) {
					t.Errorf("Install = %v, want ErrForeignUnit", err)
				}
				if err := m.Uninstall(context.Background()); !errors.Is(err, ErrForeignUnit) {
					t.Errorf("Uninstall = %v, want ErrForeignUnit", err)
				}
				if got := readFile(t, path); got != foreign {
					t.Errorf("the foreign file changed to %q", got)
				}
				if len(r.calls) > 0 {
					t.Errorf("commands ran against a foreign definition: %q", r.calls)
				}
			})
		}
	}
}

func TestSystemdUninstall(t *testing.T) {
	r := &recorder{}
	s := newSystemd(t, r)
	if err := s.Uninstall(context.Background()); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("Uninstall with nothing installed = %v, want ErrNotInstalled", err)
	}
	if len(r.calls) > 0 {
		t.Fatalf("commands ran with nothing installed: %q", r.calls)
	}
	if err := s.Install(context.Background(), exe); err != nil {
		t.Fatal(err)
	}
	r.calls = nil
	if err := s.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"systemctl disable --now " + SystemdUnit,
		"systemctl disable --now " + SystemdLauncherSocket,
		"systemctl stop " + SystemdLauncherService,
		"systemctl daemon-reload",
	}
	if !slices.Equal(r.calls, want) {
		t.Fatalf("commands = %q, want %q", r.calls, want)
	}
	for _, u := range s.units() {
		if _, err := os.Stat(u.path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s still there: %v", u.name, err)
		}
	}
}

// plistStrings returns the character data of a plist, refusing XML that is
// not well-formed.
func plistStrings(t *testing.T, plist []byte) []string {
	t.Helper()
	var strs []string
	dec := xml.NewDecoder(bytes.NewReader(plist))
	dec.Strict = true
	dec.Entity = xml.HTMLEntity
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return strs
		}
		if err != nil {
			t.Fatalf("plist is not well-formed XML: %v", err)
		}
		if cd, ok := tok.(xml.CharData); ok && strings.TrimSpace(string(cd)) != "" {
			strs = append(strs, strings.TrimSpace(string(cd)))
		}
	}
}

func TestLaunchdPlists(t *testing.T) {
	agent, err := launchdAgentPlist("/opt/a&b/localport")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(agent, []byte(Marker)) {
		t.Error("agent plist lacks the marker")
	}
	if !bytes.Contains(agent, []byte("<string>run</string>\n    <string>--service</string>\n    <string>--log-file</string>")) {
		t.Error("agent plist does not run localport run --service --log-file")
	}
	strs := plistStrings(t, agent)
	for _, want := range []string{LaunchdLabel, "/opt/a&b/localport", launchdAgentLog, AgentAccount} {
		if !slices.Contains(strs, want) {
			t.Errorf("agent plist lacks %q in %q", want, strs)
		}
	}
	if bytes.Contains(agent, []byte("StandardOutPath")) {
		t.Error("agent plist sets StandardOutPath; the agent opens its own log")
	}
	for _, want := range []string{
		"<key>ExitTimeOut</key>\n  <integer>30</integer>",
		"<key>SoftResourceLimits</key>\n  <dict>\n    <key>Core</key>\n    <integer>0</integer>",
		"<key>HardResourceLimits</key>\n  <dict>\n    <key>Core</key>\n    <integer>0</integer>",
	} {
		if !bytes.Contains(agent, []byte(want)) {
			t.Errorf("agent plist lacks %q", want)
		}
	}

	session, err := launchdLauncherPlist("/opt/a&b/localport-session", 401)
	if err != nil {
		t.Fatal(err)
	}
	strs = plistStrings(t, session)
	for _, want := range []string{LaunchdLauncherLabel, "/opt/a&b/localport-session", "launcher", launchdLauncherLog, launchdSocketName, launcher.DarwinSocketPath, "401", "432"} {
		if !slices.Contains(strs, want) {
			t.Errorf("launcher plist lacks %q in %q", want, strs)
		}
	}
	if bytes.Contains(session, []byte("UserName")) {
		t.Error("launcher plist sets UserName; it runs as root")
	}

	if _, err := launchdAgentPlist("bin/localport"); !errors.Is(err, ErrUnsafeExecutable) {
		t.Errorf("relative executable = %v, want ErrUnsafeExecutable", err)
	}
	if _, err := launchdLauncherPlist("bin/localport-session", 401); !errors.Is(err, ErrUnsafeExecutable) {
		t.Errorf("relative launcher = %v, want ErrUnsafeExecutable", err)
	}
}

func printCmd(label string) string { return launchctlPath + " print " + target(label) }

func notLoaded(labels ...string) map[string]error {
	m := map[string]error{}
	for _, l := range labels {
		m[printCmd(l)] = &CommandError{ExitCode: 113, Err: errors.New("exit status 113")}
	}
	return m
}

func TestLaunchdInstallSequence(t *testing.T) {
	r := &recorder{fail: notLoaded(LaunchdLabel, LaunchdLauncherLabel)}
	l := newLaunchd(t, r)
	launcherPlist := filepath.Join(filepath.Dir(l.plistPath), LaunchdLauncherLabel+".plist")
	if err := l.Install(context.Background(), exe); err != nil {
		t.Fatal(err)
	}
	want := []string{
		printCmd(LaunchdLauncherLabel),
		launchctlPath + " enable " + target(LaunchdLauncherLabel),
		launchctlPath + " bootstrap system " + launcherPlist,
		printCmd(LaunchdLabel),
		launchctlPath + " enable " + target(LaunchdLabel),
		launchctlPath + " bootstrap system " + l.plistPath,
	}
	if !slices.Equal(r.calls, want) {
		t.Fatalf("first install commands = %q, want %q", r.calls, want)
	}
	fi, err := os.Lstat(l.logDir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o750 {
		t.Fatalf("log dir = %v, %v, want a 0750 directory", fi, err)
	}

	// Loaded: booted out first, and bootstrapped only once launchd no
	// longer knows the label, so the new definition loads.
	r.calls = nil
	r.next = map[string][]error{printCmd(LaunchdLabel): {nil, nil}}
	if err := l.Install(context.Background(), exe); err != nil {
		t.Fatal(err)
	}
	want = slices.Insert(want, 4, launchctlPath+" bootout "+target(LaunchdLabel), printCmd(LaunchdLabel), printCmd(LaunchdLabel))
	if !slices.Equal(r.calls, want) {
		t.Fatalf("repeat install commands = %q, want %q", r.calls, want)
	}

	r.calls, r.fail = nil, nil
	if err := l.Restart(context.Background()); err != nil || !slices.Equal(r.calls, []string{launchctlPath + " kickstart -k " + target(LaunchdLabel)}) {
		t.Fatalf("Restart = %v, commands %q", err, r.calls)
	}
	r.calls = nil
	if err := l.Reload(context.Background()); err != nil || !slices.Equal(r.calls, []string{launchctlPath + " kill HUP " + target(LaunchdLabel)}) {
		t.Fatalf("Reload = %v, commands %q", err, r.calls)
	}
}

// The log directory is taken over only as a directory: a symlink in its
// place stops the install before any daemon is touched.
func TestLaunchdInstallRefusesASymlinkedLogDir(t *testing.T) {
	r := &recorder{fail: notLoaded(LaunchdLabel, LaunchdLauncherLabel)}
	l := newLaunchd(t, r)
	if err := os.Symlink(t.TempDir(), l.logDir); err != nil {
		t.Fatal(err)
	}
	if err := l.Install(context.Background(), exe); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("Install over a symlinked log dir = %v, want a refusal", err)
	}
	if len(r.calls) > 0 {
		t.Fatalf("commands ran: %q", r.calls)
	}
}

func TestLaunchdPrintFailureThatIsNotAnExitIsSurfaced(t *testing.T) {
	timedOut := &CommandError{ExitCode: -1, Err: context.DeadlineExceeded}
	r := &recorder{fail: map[string]error{printCmd(LaunchdLauncherLabel): timedOut}}
	l := newLaunchd(t, r)
	if err := l.Install(context.Background(), exe); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Install = %v, want the print timeout", err)
	}
	if len(r.calls) != 1 {
		t.Fatalf("Install went on after print failed: %q", r.calls)
	}
}

func TestLaunchdUninstall(t *testing.T) {
	r := &recorder{fail: notLoaded(LaunchdLabel, LaunchdLauncherLabel)}
	l := newLaunchd(t, r)
	if err := l.Uninstall(context.Background()); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("Uninstall with nothing installed = %v, want ErrNotInstalled", err)
	}
	if err := l.Install(context.Background(), exe); err != nil {
		t.Fatal(err)
	}
	r.calls = nil
	r.next = map[string][]error{printCmd(LaunchdLabel): {nil}, printCmd(LaunchdLauncherLabel): {nil}}
	if err := l.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{
		printCmd(LaunchdLauncherLabel), launchctlPath + " bootout " + target(LaunchdLauncherLabel), printCmd(LaunchdLauncherLabel),
		printCmd(LaunchdLabel), launchctlPath + " bootout " + target(LaunchdLabel), printCmd(LaunchdLabel),
	}
	if !slices.Equal(r.calls, want) {
		t.Fatalf("commands = %q, want %q", r.calls, want)
	}
	for _, j := range l.jobs() {
		if _, err := os.Stat(j.plist); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s still there: %v", j.plist, err)
		}
	}
}

func TestExecRunReturnsTypedErrors(t *testing.T) {
	_, err := execRun(context.Background(), "localport-no-such-command")
	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) || cmdErr.ExitCode != -1 {
		t.Fatalf("missing command = %v, want a CommandError with ExitCode -1", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	_, err = execRun(context.Background(), "false")
	if !errors.As(err, &cmdErr) || cmdErr.ExitCode != 1 {
		t.Fatalf("false = %v, want a CommandError with ExitCode 1", err)
	}
}

// Check refuses a fragment other than ours, a /dev/null mask included, and
// accepts and returns drop-ins: a type-level service.d/ file and a
// systemctl edit override in the unit's own .d/ directory.
func TestSystemdCheckRefusesAForeignFragmentAndListsDropIns(t *testing.T) {
	unitPath := filepath.Join(t.TempDir(), SystemdUnit)
	show := "systemctl show -p FragmentPath,DropInPaths " + SystemdUnit
	typeLevel := "/usr/lib/systemd/system/service.d/10-timeout-abort.conf"
	own := "/etc/systemd/system/" + SystemdUnit + ".d/override.conf"
	for _, c := range []struct {
		name, out string
		foreign   bool
		dropIns   []string
	}{
		{name: "unknown unit", out: "FragmentPath=\nDropInPaths=\n"},
		{name: "our unit", out: "FragmentPath=" + unitPath + "\nDropInPaths=\n"},
		{name: "another fragment", out: "FragmentPath=/lib/systemd/system/" + SystemdUnit + "\nDropInPaths=\n", foreign: true},
		{name: "masked", out: "FragmentPath=/dev/null\nDropInPaths=\n", foreign: true},
		{name: "a type-level drop-in", out: "FragmentPath=" + unitPath + "\nDropInPaths=" + typeLevel + "\n", dropIns: []string{typeLevel}},
		{name: "an own-directory drop-in", out: "FragmentPath=\nDropInPaths=" + typeLevel + " " + own + "\n", dropIns: []string{typeLevel, own}},
	} {
		r := &recorder{out: map[string]string{show: c.out}}
		s := systemd{unitPath: unitPath, systemctl: "systemctl", run: r.run}
		dropIns, err := s.Check()
		if c.foreign != errors.Is(err, ErrForeignUnit) || (!c.foreign && err != nil) {
			t.Errorf("%s: Check = %v, foreign %v", c.name, err, c.foreign)
		}
		if !slices.Equal(dropIns, c.dropIns) {
			t.Errorf("%s: drop-ins = %q, want %q", c.name, dropIns, c.dropIns)
		}
	}
	// The launcher units are checked the same way.
	r := &recorder{out: map[string]string{"systemctl show -p FragmentPath,DropInPaths " + SystemdLauncherSocket: "FragmentPath=/dev/null\n"}}
	if _, err := (systemd{unitPath: unitPath, systemctl: "systemctl", run: r.run}).Check(); !errors.Is(err, ErrForeignUnit) {
		t.Errorf("masked launcher socket: Check = %v, want ErrForeignUnit", err)
	}
}

func TestLaunchdCheckRefusesALoadedLabelWithoutOurPlist(t *testing.T) {
	r := &recorder{}
	l := newLaunchd(t, r)
	if _, err := l.Check(); !errors.Is(err, ErrForeignUnit) {
		t.Fatalf("Check with the label loaded and no plist = %v, want ErrForeignUnit", err)
	}
	r.fail = notLoaded(LaunchdLabel, LaunchdLauncherLabel)
	if _, err := l.Check(); err != nil {
		t.Fatalf("Check with nothing loaded = %v", err)
	}
}

func TestLaunchdBootoutWaitIsBounded(t *testing.T) {
	r := &recorder{}
	l := newLaunchd(t, r)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := l.bootoutIfLoaded(ctx, LaunchdLabel); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bootout that never finishes = %v, want a deadline error", err)
	}
}

// MainPID reports the main process only while the manager calls the service
// running; every transient or stopped state reports 0.
func TestSystemdMainPID(t *testing.T) {
	show := "/bin/systemctl show -p MainPID,ActiveState " + SystemdUnit
	for _, c := range []struct {
		out  string
		want int
	}{
		{"MainPID=4242\nActiveState=active\n", 4242},
		{"MainPID=4242\nActiveState=activating\n", 0},
		{"MainPID=4242\nActiveState=deactivating\n", 0},
		{"MainPID=0\nActiveState=inactive\n", 0},
	} {
		r := &recorder{out: map[string]string{show: c.out}}
		s := systemd{unitPath: filepath.Join(t.TempDir(), SystemdUnit), systemctl: "/bin/systemctl", run: r.run}
		if pid, err := s.MainPID(context.Background()); err != nil || pid != c.want {
			t.Fatalf("MainPID for %q = %d, %v, want %d", c.out, pid, err, c.want)
		}
	}
}

func TestLaunchdMainPID(t *testing.T) {
	p := printCmd(LaunchdLabel)
	for _, c := range []struct {
		out  string
		err  error
		want int
	}{
		{out: "system/io.localport.device = {\n\tactive count = 1\n\tstate = running\n\tpid = 4242\n\tendpoints = {\n\t\tpid = 1\n\t}\n}\n", want: 4242},
		{out: "system/io.localport.device = {\n\tstate = spawn scheduled\n}\n", want: 0},
		{err: &CommandError{ExitCode: 113, Err: errors.New("exit status 113")}, want: 0},
	} {
		r := &recorder{out: map[string]string{p: c.out}, fail: map[string]error{p: c.err}}
		if pid, err := newLaunchd(t, r).MainPID(context.Background()); err != nil || pid != c.want {
			t.Fatalf("MainPID for %q = %d, %v, want %d", c.out, pid, err, c.want)
		}
	}
}

// Only launchctl print's not-found exit (113, checked on macOS 2026-11-12)
// means an unloaded label; any other failure is an error, for MainPID and
// for loaded.
func TestLaunchdPrintFailuresOtherThanNotFoundAreErrors(t *testing.T) {
	p := printCmd(LaunchdLabel)
	failed := &CommandError{ExitCode: 5, Err: errors.New("exit status 5")}
	r := &recorder{fail: map[string]error{p: failed}}
	if _, err := newLaunchd(t, r).MainPID(context.Background()); !errors.Is(err, failed) {
		t.Fatalf("MainPID on exit 5 = %v, want the failure", err)
	}
	if _, err := newLaunchd(t, r).loaded(context.Background(), LaunchdLabel); !errors.Is(err, failed) {
		t.Fatalf("loaded on exit 5 = %v, want the failure", err)
	}
	r = &recorder{fail: map[string]error{p: &CommandError{ExitCode: 113, Err: errors.New("exit status 113")}}}
	if ok, err := newLaunchd(t, r).loaded(context.Background(), LaunchdLabel); err != nil || ok {
		t.Fatalf("loaded on exit 113 = %v, %v; want not loaded", ok, err)
	}
}

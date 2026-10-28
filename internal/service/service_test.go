package service

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
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

func newLaunchd(t *testing.T, r *recorder) launchd {
	dir := t.TempDir()
	return launchd{plistPath: filepath.Join(dir, LaunchdLabel+".plist"), logPath: filepath.Join(dir, "localport-device.log"), logUID: os.Getuid(), run: r.run}
}

// Install creates the log owner-only before bootstrap, tightens an existing
// one, and refuses a log path that is not a regular file.
func TestLaunchdInstallPreparesTheLog(t *testing.T) {
	notLoaded := &CommandError{Command: launchctlPath + " print " + launchdTarget, ExitCode: 113, Err: errors.New("exit status 113")}
	r := &recorder{fail: map[string]error{launchctlPath + " print " + launchdTarget: notLoaded}}
	l := newLaunchd(t, r)
	mode := func() os.FileMode {
		t.Helper()
		fi, err := os.Lstat(l.logPath)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Mode()
	}
	if err := l.Install(context.Background(), exe); err != nil {
		t.Fatal(err)
	}
	if got := mode(); got != 0o600 {
		t.Fatalf("created log mode = %v, want 0600", got)
	}
	if err := os.Chmod(l.logPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := l.Install(context.Background(), exe); err != nil {
		t.Fatal(err)
	}
	if got := mode(); got != 0o600 {
		t.Fatalf("existing log mode = %v, want 0600", got)
	}

	if err := os.Remove(l.logPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "elsewhere"), l.logPath); err != nil {
		t.Fatal(err)
	}
	r.calls = nil
	if err := l.Install(context.Background(), exe); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("Install over a symlinked log = %v, want a refusal", err)
	}
	if slices.Contains(r.calls, launchctlPath+" bootstrap system "+l.plistPath) {
		t.Fatal("bootstrapped with an unprepared log")
	}
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

func TestSystemdUnitFile(t *testing.T) {
	unit, err := systemdUnitFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(unit), "\n")
	for _, want := range []string{
		"# " + Marker,
		"User=root",
		"ExecStart=" + exe + " run --service",
		"Restart=always",
		"KillMode=process",
		"NoNewPrivileges=no",
		"LimitCORE=0",
		"WantedBy=multi-user.target",
	} {
		if !slices.Contains(lines, want) {
			t.Errorf("unit lacks the line %q", want)
		}
	}
	// Directives that would confine a session's shell appear only in comments.
	for _, line := range lines {
		for _, banned := range []string{"ProtectSystem=", "ProtectHome=", "PrivateTmp=", "ReadWritePaths=", "CapabilityBoundingSet=", "SystemCallFilter="} {
			if strings.HasPrefix(line, banned) {
				t.Errorf("unit sets %q, which confines the shells sessions start", line)
			}
		}
	}
}

func TestSystemdUnitFileRefusesUnsafeExecutable(t *testing.T) {
	for _, bad := range []string{"localport", "/opt/my tools/localport", "/opt/%h/localport", "/opt/$HOME/localport", "/opt/\"x\"/localport", "/opt/x\n/localport"} {
		if _, err := systemdUnitFile(bad); !errors.Is(err, ErrUnsafeExecutable) {
			t.Errorf("systemdUnitFile(%q) = %v, want ErrUnsafeExecutable", bad, err)
		}
	}
}

func TestSystemdInstallSequence(t *testing.T) {
	r := &recorder{}
	s := systemd{unitPath: filepath.Join(t.TempDir(), SystemdUnit), systemctl: "systemctl", run: r.run}
	if err := s.Install(context.Background(), exe); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"systemctl daemon-reload",
		"systemctl enable " + SystemdUnit,
		"systemctl restart " + SystemdUnit,
	}
	if !slices.Equal(r.calls, want) {
		t.Fatalf("commands = %q, want %q", r.calls, want)
	}
	if installed, err := s.Installed(); err != nil || !installed {
		t.Fatalf("Installed = %v, %v after Install", installed, err)
	}
	if fi, err := os.Stat(s.unitPath); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("unit file mode = %v, %v, want 0644", fi, err)
	}

	// A repeat install overwrites its own file and restarts the service.
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
}

func TestSystemdCommandFailureIsSurfaced(t *testing.T) {
	failure := &CommandError{Command: "systemctl enable " + SystemdUnit, ExitCode: 1, Err: errors.New("exit status 1")}
	r := &recorder{fail: map[string]error{"systemctl enable " + SystemdUnit: failure}}
	s := systemd{unitPath: filepath.Join(t.TempDir(), SystemdUnit), systemctl: "systemctl", run: r.run}
	err := s.Install(context.Background(), exe)
	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) || cmdErr.ExitCode != 1 {
		t.Fatalf("Install = %v, want the enable CommandError", err)
	}
	if slices.Contains(r.calls, "systemctl restart "+SystemdUnit) {
		t.Fatal("Install went on after a failed command")
	}
}

// The marker guards a file localport did not write: install, check and
// uninstall refuse it, leave it unchanged and run no service command.
func TestForeignDefinitionIsRefused(t *testing.T) {
	dir := t.TempDir()
	const foreign = "[Service]\nExecStart=/usr/bin/someone-else\n"
	managers := map[string]Manager{
		"systemd": systemd{unitPath: filepath.Join(dir, SystemdUnit)},
		"launchd": launchd{plistPath: filepath.Join(dir, LaunchdLabel+".plist")},
	}
	for name, m := range managers {
		t.Run(name, func(t *testing.T) {
			r := &recorder{}
			var path string
			switch v := m.(type) {
			case systemd:
				v.run, path = r.run, v.unitPath
				m = v
			case launchd:
				v.run, path = r.run, v.plistPath
				m = v
			}
			writeFile(t, path, foreign)

			if _, err := m.Check(); !errors.Is(err, ErrForeignUnit) {
				t.Errorf("Check = %v, want ErrForeignUnit", err)
			}
			if _, err := m.Installed(); !errors.Is(err, ErrForeignUnit) {
				t.Errorf("Installed = %v, want ErrForeignUnit", err)
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

func TestSystemdUninstall(t *testing.T) {
	r := &recorder{}
	s := systemd{unitPath: filepath.Join(t.TempDir(), SystemdUnit), systemctl: "systemctl", run: r.run}
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
	want := []string{"systemctl disable --now " + SystemdUnit, "systemctl daemon-reload"}
	if !slices.Equal(r.calls, want) {
		t.Fatalf("commands = %q, want %q", r.calls, want)
	}
	if _, err := os.Stat(s.unitPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unit file still there: %v", err)
	}
}

func TestLaunchdPlist(t *testing.T) {
	plist, err := launchdPlist("/opt/a&b/localport")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(plist, []byte(Marker)) {
		t.Error("plist lacks the marker")
	}
	if !bytes.Contains(plist, []byte("<string>run</string>\n    <string>--service</string>")) {
		t.Error("plist does not run localport run --service")
	}
	var strs []string
	dec := xml.NewDecoder(bytes.NewReader(plist))
	dec.Strict = true
	dec.Entity = xml.HTMLEntity
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("plist is not well-formed XML: %v", err)
		}
		if cd, ok := tok.(xml.CharData); ok && strings.TrimSpace(string(cd)) != "" {
			strs = append(strs, strings.TrimSpace(string(cd)))
		}
	}
	for _, want := range []string{LaunchdLabel, "/opt/a&b/localport", "run", launchdLog} {
		if !slices.Contains(strs, want) {
			t.Errorf("plist lacks %q in %q", want, strs)
		}
	}
	if _, err := launchdPlist("bin/localport"); !errors.Is(err, ErrUnsafeExecutable) {
		t.Errorf("relative executable = %v, want ErrUnsafeExecutable", err)
	}
}

func TestLaunchdInstallSequence(t *testing.T) {
	notLoaded := &CommandError{Command: launchctlPath + " print " + launchdTarget, ExitCode: 113, Err: errors.New("exit status 113")}
	r := &recorder{fail: map[string]error{launchctlPath + " print " + launchdTarget: notLoaded}}
	l := newLaunchd(t, r)
	if err := l.Install(context.Background(), exe); err != nil {
		t.Fatal(err)
	}
	want := []string{
		launchctlPath + " print " + launchdTarget,
		launchctlPath + " enable " + launchdTarget,
		launchctlPath + " bootstrap system " + l.plistPath,
	}
	if !slices.Equal(r.calls, want) {
		t.Fatalf("first install commands = %q, want %q", r.calls, want)
	}

	// Loaded: booted out first, and bootstrapped only once launchd no
	// longer knows the label, so the new definition and credential load.
	r.calls = nil
	r.next = map[string][]error{launchctlPath + " print " + launchdTarget: {nil, nil}}
	if err := l.Install(context.Background(), exe); err != nil {
		t.Fatal(err)
	}
	want = slices.Insert(want, 1, launchctlPath+" bootout "+launchdTarget, launchctlPath+" print "+launchdTarget, launchctlPath+" print "+launchdTarget)
	if !slices.Equal(r.calls, want) {
		t.Fatalf("repeat install commands = %q, want %q", r.calls, want)
	}

	r.calls, r.fail = nil, nil
	if err := l.Restart(context.Background()); err != nil || !slices.Equal(r.calls, []string{launchctlPath + " kickstart -k " + launchdTarget}) {
		t.Fatalf("Restart = %v, commands %q", err, r.calls)
	}
}

func TestLaunchdPrintFailureThatIsNotAnExitIsSurfaced(t *testing.T) {
	timedOut := &CommandError{Command: launchctlPath + " print " + launchdTarget, ExitCode: -1, Err: context.DeadlineExceeded}
	r := &recorder{fail: map[string]error{launchctlPath + " print " + launchdTarget: timedOut}}
	l := newLaunchd(t, r)
	if err := l.Install(context.Background(), exe); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Install = %v, want the print timeout", err)
	}
	if len(r.calls) != 1 {
		t.Fatalf("Install went on after print failed: %q", r.calls)
	}
}

func TestLaunchdUninstall(t *testing.T) {
	notLoaded := &CommandError{ExitCode: 113, Err: errors.New("exit status 113")}
	r := &recorder{fail: map[string]error{launchctlPath + " print " + launchdTarget: notLoaded}}
	l := newLaunchd(t, r)
	if err := l.Uninstall(context.Background()); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("Uninstall with nothing installed = %v, want ErrNotInstalled", err)
	}
	if err := l.Install(context.Background(), exe); err != nil {
		t.Fatal(err)
	}
	r.calls = nil
	r.next = map[string][]error{launchctlPath + " print " + launchdTarget: {nil}}
	if err := l.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{launchctlPath + " print " + launchdTarget, launchctlPath + " bootout " + launchdTarget, launchctlPath + " print " + launchdTarget}
	if !slices.Equal(r.calls, want) {
		t.Fatalf("commands = %q, want %q", r.calls, want)
	}
	if _, err := os.Stat(l.plistPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("plist still there: %v", err)
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
}

func TestLaunchdCheckRefusesALoadedLabelWithoutOurPlist(t *testing.T) {
	r := &recorder{}
	l := newLaunchd(t, r)
	if _, err := l.Check(); !errors.Is(err, ErrForeignUnit) {
		t.Fatalf("Check with the label loaded and no plist = %v, want ErrForeignUnit", err)
	}
	r.fail = map[string]error{launchctlPath + " print " + launchdTarget: &CommandError{ExitCode: 113, Err: errors.New("exit status 113")}}
	if _, err := l.Check(); err != nil {
		t.Fatalf("Check with nothing loaded = %v", err)
	}
}

func TestLaunchdBootoutWaitIsBounded(t *testing.T) {
	r := &recorder{}
	l := newLaunchd(t, r)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := l.bootoutIfLoaded(ctx); !errors.Is(err, context.DeadlineExceeded) {
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
	print := launchctlPath + " print " + launchdTarget
	for _, c := range []struct {
		out  string
		err  error
		want int
	}{
		{out: "system/io.localport.device = {\n\tactive count = 1\n\tstate = running\n\tpid = 4242\n\tendpoints = {\n\t\tpid = 1\n\t}\n}\n", want: 4242},
		{out: "system/io.localport.device = {\n\tstate = spawn scheduled\n}\n", want: 0},
		{err: &CommandError{ExitCode: 113, Err: errors.New("exit status 113")}, want: 0},
	} {
		r := &recorder{out: map[string]string{print: c.out}, fail: map[string]error{print: c.err}}
		if pid, err := newLaunchd(t, r).MainPID(context.Background()); err != nil || pid != c.want {
			t.Fatalf("MainPID for %q = %d, %v, want %d", c.out, pid, err, c.want)
		}
	}
}

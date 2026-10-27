package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
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

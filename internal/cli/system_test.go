package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type fakeInstallHost struct {
	notElevated bool
	dirErr      error
	stopErr     error
	stopped     []string
	started     [][]string
	installed   bool
	reregErr    error
	reregs      []string
	foreign     []string
	uninstalls  []bool
	path        string
	expandable  bool
	writes      int
	broadcasts  int
	systemRoot  string
}

func (f *fakeInstallHost) elevated() bool                 { return !f.notElevated }
func (f *fakeInstallHost) prepareInstallDir(string) error { return f.dirErr }
func (f *fakeInstallHost) stopServices(context.Context) ([]string, error) {
	return f.stopped, f.stopErr
}
func (f *fakeInstallHost) startServices(_ context.Context, names []string) error {
	f.started = append(f.started, names)
	return nil
}
func (f *fakeInstallHost) servicesInstalled() (bool, error) { return f.installed, nil }
func (f *fakeInstallHost) reregister(_ context.Context, dir string) error {
	f.reregs = append(f.reregs, dir)
	return f.reregErr
}
func (f *fakeInstallHost) foreignServicesIn(string) ([]string, error) { return f.foreign, nil }
func (f *fakeInstallHost) uninstallServices(purge bool) error {
	f.uninstalls = append(f.uninstalls, purge)
	return nil
}
func (f *fakeInstallHost) readPath() (string, bool, error) { return f.path, f.expandable, nil }
func (f *fakeInstallHost) writePath(v string, expandable bool) error {
	f.path, f.expandable, f.writes = v, expandable, f.writes+1
	return nil
}
func (f *fakeInstallHost) broadcastEnvironment() error { f.broadcasts++; return nil }
func (f *fakeInstallHost) expand(s string) string {
	root := f.systemRoot
	if root == "" {
		root = `C:\Windows`
	}
	return strings.ReplaceAll(s, "%SystemRoot%", root)
}

func absDir(t *testing.T) string { t.Helper(); return t.TempDir() }

// Every step refuses unless elevated, before it does anything.
func TestSystemStepsRefuseWithoutElevation(t *testing.T) {
	dir := absDir(t)
	for _, args := range [][]string{{"preflight", dir}, {"stop", dir}, {"commit", dir, ".staging-x"}, {"reregister", dir}, {"preuninstall", dir}, {"path", "add", dir}} {
		h := &fakeInstallHost{notElevated: true, installed: true}
		if err := runSystemSteps(context.Background(), h, args); !errors.Is(err, errInstallerNotElevated) {
			t.Errorf("%v = %v, want errInstallerNotElevated", args, err)
		}
		if len(h.reregs)+len(h.uninstalls)+h.writes != 0 {
			t.Errorf("%v acted without elevation", args)
		}
	}
}

func TestSystemPreflightAndStop(t *testing.T) {
	dir := absDir(t)
	unsafe := errors.New("Users can add files")
	if err := runSystemSteps(context.Background(), &fakeInstallHost{dirErr: unsafe}, []string{"preflight", dir}); !errors.Is(err, errInstallDirUnsafe) || !errors.Is(err, unsafe) {
		t.Fatalf("preflight = %v, want errInstallDirUnsafe", err)
	}
	if err := runSystemSteps(context.Background(), &fakeInstallHost{}, []string{"preflight", "relative"}); err == nil {
		t.Fatal("preflight accepted a relative directory")
	}
	h := &fakeInstallHost{stopped: []string{"localport-device"}, stopErr: errors.New("timeout")}
	if err := runSystemSteps(context.Background(), h, []string{"stop", dir}); !errors.Is(err, errServicesNotStopped) {
		t.Fatalf("stop = %v, want errServicesNotStopped", err)
	}
	if len(h.started) != 1 || !slices.Equal(h.started[0], []string{"localport-device"}) {
		t.Fatalf("started after a failed stop = %v, want what it stopped", h.started)
	}
}

func stage(t *testing.T, dir, staging, release string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, staging), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range installBinaries {
		if err := os.WriteFile(filepath.Join(dir, staging, name), []byte(release), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func readBinaries(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	for _, name := range installBinaries {
		raw, _ := os.ReadFile(filepath.Join(dir, name))
		out = append(out, string(raw))
	}
	return out
}

// Commit puts both staged executables in place and cleans leftovers of
// earlier runs; a failure on the second restores both previous files and
// restarts the owned services.
func TestSystemCommit(t *testing.T) {
	dir := absDir(t)
	stage(t, dir, ".staging-old", "v1")
	if err := os.WriteFile(filepath.Join(dir, "localport.exe.old"), []byte("v0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := runSystemSteps(context.Background(), &fakeInstallHost{}, []string{"commit", dir, ".staging-old"}); err != nil {
		t.Fatal(err)
	}
	stage(t, dir, ".staging-left", "stale")
	stage(t, dir, ".staging-new", "v2")
	if err := runSystemSteps(context.Background(), &fakeInstallHost{}, []string{"commit", dir, ".staging-new"}); err != nil {
		t.Fatal(err)
	}
	if got := readBinaries(t, dir); !slices.Equal(got, []string{"v2", "v2"}) {
		t.Fatalf("binaries = %v, want v2", got)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), stagingPrefix) || strings.HasSuffix(e.Name(), ".old") {
			t.Errorf("leftover %s", e.Name())
		}
	}

	// The second executable cannot be moved: a directory sits in its place.
	stage(t, dir, ".staging-bad", "v3")
	session := filepath.Join(dir, ".staging-bad", installBinaries[1])
	if err := os.Remove(session); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(session, 0o755); err != nil {
		t.Fatal(err)
	}
	h := &fakeInstallHost{installed: true}
	if err := runSystemSteps(context.Background(), h, []string{"commit", dir, ".staging-bad"}); !errors.Is(err, errInstallNotCommitted) {
		t.Fatalf("commit with a bad staged file = %v, want errInstallNotCommitted", err)
	}
	if got := readBinaries(t, dir); !slices.Equal(got, []string{"v2", "v2"}) {
		t.Fatalf("binaries after a refused commit = %v, want v2 kept", got)
	}
	if len(h.started) != 1 {
		t.Fatalf("services started %d times after a refused commit, want 1", len(h.started))
	}

	// The rename of the second file fails after the first moved.
	stage(t, dir, ".staging-held", "v4")
	if err := os.Mkdir(filepath.Join(dir, installBinaries[1]+".old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, installBinaries[1]+".old", "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runSystemSteps(context.Background(), &fakeInstallHost{}, []string{"commit", dir, ".staging-held"}); !errors.Is(err, errInstallNotCommitted) {
		t.Fatalf("commit with the second move refused = %v", err)
	}
	if got := readBinaries(t, dir); !slices.Equal(got, []string{"v2", "v2"}) {
		t.Fatalf("binaries after a rolled-back commit = %v, want both v2", got)
	}
}

// Commit takes only a staging directory directly inside the install
// directory, even when the path it names holds staged files.
func TestSystemCommitRefusesStagingOutsideTheDirectory(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "install")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stage(t, base, ".staging-outside", "foreign")
	for _, staging := range []string{"../.staging-outside", filepath.Join(base, ".staging-outside"), "staged"} {
		if err := runSystemSteps(context.Background(), &fakeInstallHost{}, []string{"commit", dir, staging}); err == nil {
			t.Errorf("commit accepted staging %q", staging)
		}
	}
	if got := readBinaries(t, dir); !slices.Equal(got, []string{"", ""}) {
		t.Fatalf("binaries = %v, want none installed", got)
	}
}

// Reregister runs only with owned services; preuninstall refuses a foreign
// service inside the directory and passes --purge on.
func TestSystemReregisterAndPreuninstall(t *testing.T) {
	dir := absDir(t)
	h := &fakeInstallHost{}
	if err := runSystemSteps(context.Background(), h, []string{"reregister", dir}); err != nil || len(h.reregs) != 0 {
		t.Fatalf("reregister without services = %v, %v", err, h.reregs)
	}
	h = &fakeInstallHost{installed: true, reregErr: errors.New("sc failed")}
	if err := runSystemSteps(context.Background(), h, []string{"reregister", dir}); !errors.Is(err, errServicesNotRestored) || !slices.Equal(h.reregs, []string{dir}) {
		t.Fatalf("reregister = %v, %v", err, h.reregs)
	}
	h = &fakeInstallHost{foreign: []string{"OtherSvc"}}
	if err := runSystemSteps(context.Background(), h, []string{"preuninstall", dir}); !errors.Is(err, errForeignServiceInDir) || len(h.uninstalls) != 0 {
		t.Fatalf("preuninstall with a foreign service = %v, uninstalls %v", err, h.uninstalls)
	}
	h = &fakeInstallHost{}
	if err := runSystemSteps(context.Background(), h, []string{"preuninstall", dir, "--purge"}); err != nil || !slices.Equal(h.uninstalls, []bool{true}) {
		t.Fatalf("preuninstall --purge = %v, %v", err, h.uninstalls)
	}
}

// Path edits keep every other entry and the value's type, match case- and
// separator-insensitively and after expansion, and are idempotent.
func TestSystemPath(t *testing.T) {
	dir := absDir(t)
	long := strings.Repeat(`C:\x;`, 2000) + `%SystemRoot%\system32`
	for _, tc := range []struct {
		name, op, before, after string
	}{
		{"add", "add", `%SystemRoot%\system32;C:\Tools`, `%SystemRoot%\system32;C:\Tools;` + dir},
		{"re-add", "add", `C:\Tools;` + strings.ToUpper(dir) + `\`, `C:\Tools;` + strings.ToUpper(dir) + `\`},
		{"add to empty", "add", ``, dir},
		{"add after trailing separator", "add", `C:\Tools;`, `C:\Tools;` + dir},
		{"remove", "remove", `C:\Tools;` + dir + `;%SystemRoot%`, `C:\Tools;%SystemRoot%`},
		{"remove absent", "remove", `C:\Tools`, `C:\Tools`},
		{"long value kept", "add", long, long + ";" + dir},
	} {
		h := &fakeInstallHost{path: tc.before, expandable: true}
		if err := runSystemSteps(context.Background(), h, []string{"path", tc.op, dir}); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if h.path != tc.after || !h.expandable {
			t.Errorf("%s: Path = %q (expandable %v), want %q", tc.name, h.path, h.expandable, tc.after)
		}
		if changed := tc.before != tc.after; (h.writes == 1) != changed || (h.broadcasts == 1) != changed {
			t.Errorf("%s: writes %d, broadcasts %d", tc.name, h.writes, h.broadcasts)
		}
	}
	// An entry that expands to the directory counts as present.
	h := &fakeInstallHost{path: `C:\Tools;%SystemRoot%`, systemRoot: dir}
	if err := runSystemSteps(context.Background(), h, []string{"path", "add", dir}); err != nil || h.writes != 0 {
		t.Fatalf("an entry expanding to the directory was added again: %v, %q", err, h.path)
	}
	h = &fakeInstallHost{path: `C:\Tools`}
	if err := runSystemSteps(context.Background(), h, []string{"path", "add", filepath.Join(dir, "missing")}); !errors.Is(err, errMachinePathNotSet) || h.writes != 0 {
		t.Fatalf("add of a missing directory = %v, writes %d", err, h.writes)
	}
}

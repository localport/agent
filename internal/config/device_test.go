package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/security"
)

const testIdentity = "01kpq7x2abcd34/device/tun12345.gw-01"

func userLocalConfig(t *testing.T) LocalConfigFile {
	t.Helper()
	t.Setenv(identity.HomeEnv, t.TempDir())
	f, err := UserLocalConfig()
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestLocalConfigRoundTrips(t *testing.T) {
	f := userLocalConfig(t)
	ref, err := identity.ParseDeviceRef(testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	filesRoot := t.TempDir()
	want := &LocalConfig{Devices: []LocalDevice{{
		Identity:  ref,
		Enable:    []Capability{CapabilityDesktop},
		RDP:       DefaultRDPTarget,
		VNC:       "192.168.1.50:5901",
		FilesRoot: filesRoot,
	}}}
	if runtime.GOOS != "windows" {
		want.Devices[0].Enable = []Capability{CapabilityTerminal, CapabilityFiles, CapabilityDesktop}
		want.Devices[0].Logins = []string{"pi", "_svc-1"}
	}
	if err := WriteLocal(f, want, want.Devices[0].Identity); err != nil {
		t.Fatalf("WriteLocal: %v", err)
	}
	got, err := LoadLocal(f)
	if err != nil {
		t.Fatalf("LoadLocal: %v", err)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("round trip:\n got %+v\nwant %+v", got, want)
	}

	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(f.Path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("file mode %#o, want 0600", perm)
	}
	dirInfo, err := os.Stat(filepath.Dir(f.Path))
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Fatalf("directory mode %#o, want 0700", perm)
	}
}

// A local config with comments and a comma-separated allow_ports loads.
func TestLocalConfigReadsTheDocumentedShape(t *testing.T) {
	cfg, err := parseLocal([]byte(`version: 2
devices:
  - identity: `+testIdentity+`
    host: 192.168.1.50        # optional
    allow_ports: 502,80
    enable: [desktop]
    rdp: 127.0.0.1:3389       # optional
  - identity: 01kpq7x2abcd34/device/tun12345.hub
    allow_ports: 502
    host: fd00::1
`), "linux")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	d := cfg.Devices[0]
	if d.Host != "192.168.1.50" || d.AllowPorts.String() != "80,502" || d.RDP != DefaultRDPTarget {
		t.Fatalf("device = %+v", d)
	}
	if got := cfg.Devices[1].AllowPorts.String(); got != "502" || cfg.Devices[1].Host != "fd00::1" {
		t.Fatalf("device 2 = %+v", cfg.Devices[1])
	}
}

func TestLocalConfigRefusesAFleetToken(t *testing.T) {
	for _, body := range []string{
		"version: 2\nfleets:\n  - token: t\n",
		"version: 2\nfleets: {}\n",
		"version: 2\nfleets:\n",
		"version: 1\nfleets:\n  - token: t\n    devices:\n      - name: gw\n",
	} {
		if _, err := parseLocal([]byte(body), "linux"); !errors.Is(err, ErrFleetTokenRetired) {
			t.Fatalf("parse(%q) = %v, want ErrFleetTokenRetired", body, err)
		}
	}
}

func TestLocalConfigRefusesAnOpenFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits carry no policy on Windows; the DACL check is tested in security")
	}
	f := userLocalConfig(t)
	ref, _ := identity.ParseDeviceRef(testIdentity)
	if err := WriteLocal(f, &LocalConfig{Devices: []LocalDevice{{Identity: ref}}}, ref); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.Path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLocal(f); !errors.Is(err, security.ErrUntrustedPath) {
		t.Fatalf("LoadLocal(0644) = %v, want ErrUntrustedPath", err)
	}
}

// Another account that can write the config directory can replace the file.
func TestLocalConfigRefusesAGroupWritableDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits carry no policy on Windows")
	}
	f := userLocalConfig(t)
	ref, _ := identity.ParseDeviceRef(testIdentity)
	if err := WriteLocal(f, &LocalConfig{Devices: []LocalDevice{{Identity: ref}}}, ref); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o770, 0o702} {
		if err := os.Chmod(filepath.Dir(f.Path), mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadLocal(f); !errors.Is(err, security.ErrUntrustedPath) {
			t.Fatalf("LoadLocal with directory %#o = %v, want ErrUntrustedPath", mode, err)
		}
	}
}

// files_root existence is checked when the config is written.
func TestWriteLocalChecksTheFilesRootExists(t *testing.T) {
	f := userLocalConfig(t)
	ref, _ := identity.ParseDeviceRef(testIdentity)
	file := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{filepath.Join(t.TempDir(), "missing"), file} {
		cfg := &LocalConfig{Devices: []LocalDevice{{Identity: ref, FilesRoot: root}}}
		if err := WriteLocal(f, cfg, cfg.Devices[0].Identity); err == nil {
			t.Fatalf("WriteLocal(files_root %s) must be refused", root)
		}
		if err := CheckFilesRoot(root); err == nil {
			t.Fatalf("CheckFilesRoot(%s) must be refused", root)
		}
	}
	if err := CheckFilesRoot(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("CheckFilesRoot(missing) = %v, want fs.ErrNotExist", err)
	}
	if err := CheckFilesRoot(t.TempDir()); err != nil {
		t.Fatalf("CheckFilesRoot(existing dir) = %v", err)
	}
	if _, err := os.Stat(f.Path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused config reached disk: %v", err)
	}
}

// A config in a directory owned by another account is refused before it is
// read. /usr is root-owned on every Unix this agent supports.
func TestLocalConfigRefusesADirectoryOwnedBySomeoneElse(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a Unix account other than root")
	}
	f := LocalConfigFile{Path: "/usr/agent.yaml", Base: "/usr"}
	if _, err := LoadLocal(f); !errors.Is(err, security.ErrUntrustedPath) {
		t.Fatalf("LoadLocal = %v, want ErrUntrustedPath", err)
	}
}

func TestLocalConfigMissingFileIsNotExist(t *testing.T) {
	f := userLocalConfig(t)
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLocal(f); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("LoadLocal = %v, want fs.ErrNotExist", err)
	}
}

// Each rule refuses on load. WriteLocal runs the same validation.
func TestLocalConfigValidation(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "plain")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	logins17 := make([]string, 17)
	for i := range logins17 {
		logins17[i] = fmt.Sprintf("u%d", i)
	}
	device := func(fields string) string {
		return "version: 2\ndevices:\n  - identity: " + testIdentity + "\n" + fields
	}
	cases := []struct {
		name, body, goos string
		// want is a substring of the refusal that names the rule.
		want string
	}{
		{"version 1", "version: 1\ndevices:\n  - identity: " + testIdentity + "\n", "linux", "unsupported local config version 1"},
		{"no devices", "version: 2\ndevices: []\n", "linux", "lists no devices"},
		{"unknown key", device("    hosts: 10.0.0.2\n"), "linux", "field hosts not found"},
		{"identity of another kind", "version: 2\ndevices:\n  - identity: 01kpq7x2abcd34/client/gw-01\n", "linux", "is not of the form <team>/device/<tunnel>.<prefix>"},
		{"identity without tunnel", "version: 2\ndevices:\n  - identity: 01kpq7x2abcd34/device/gw-01\n", "linux", "is not of the form <team>/device/<tunnel>.<prefix>"},
		{"duplicate device", device("") + "  - identity: " + testIdentity + "\n", "linux", "is listed twice"},
		{"host with port", device("    host: 10.0.0.2:502\n"), "linux", "host takes an address without a port"},
		{"host with scheme", device("    host: tcp://10.0.0.2\n"), "linux", "host takes an address without a scheme"},
		{"allow_ports out of range", device("    allow_ports: 70000\n"), "linux", "allow_ports:"},
		{"login of digits only", device("    logins: ['1000']\n"), "linux", `login "1000" is not a valid user name`},
		{"login of a dash and digits", device("    logins: ['-1']\n"), "linux", `login "-1" is not a valid user name`},
		{"login with a colon", device("    logins: ['a:b']\n"), "linux", `login "a:b" is not a valid user name`},
		{"login with a comma", device("    logins: ['a,b']\n"), "linux", `login "a,b" is not a valid user name`},
		{"login with a leading space", device("    logins: [' pi']\n"), "linux", "is not a valid user name"},
		{"login dot", device("    logins: ['.']\n"), "linux", `login "." is not a valid user name`},
		{"login too long", device("    logins: [" + strings.Repeat("a", 256) + "]\n"), "linux", "is not a valid user name"},
		{"login with a slash", device("    logins: [a/b]\n"), "linux", `login "a/b" is not a valid user name`},
		{"duplicate login", device("    logins: [pi, pi]\n"), "linux", `login "pi" is listed twice`},
		{"17 logins", device("    logins: [" + strings.Join(logins17, ", ") + "]\n"), "linux", "17 logins, over the limit of 16"},
		{"unknown capability", device("    enable: [shell]\n"), "linux", `enable "shell" is not one of terminal, files, desktop`},
		{"duplicate capability", device("    enable: [files, files]\n"), "linux", "enable lists files twice"},
		{"terminal with host", device("    host: 10.0.0.2\n    enable: [terminal]\n"), "linux", "terminal: terminal and files act on this machine only"},
		{"files with host", device("    host: 10.0.0.2\n    enable: [files]\n"), "linux", "files: terminal and files act on this machine only"},
		{"logins without terminal or files", device("    enable: [desktop]\n    rdp: 127.0.0.1:3389\n    logins: [pi]\n"), "linux", "logins apply only to a device that enables terminal or files"},
		{"password logins off Windows", device("    enable: [terminal]\n    logins: [pi]\n    password_logins: [pi]\n"), "linux",
			"password_logins is available on Windows only"},
		{"password login not a login", device("    enable: [terminal]\n    logins: [alice]\n    password_logins: [bob]\n"), "windows",
			`password login "bob" is not one of logins`},
		{"duplicate password login", device("    enable: [terminal]\n    logins: [alice]\n    password_logins: [alice, alice]\n"), "windows",
			`password login "alice" is listed twice`},
		{"desktop without a target", device("    enable: [desktop]\n"), "linux", "desktop needs an rdp or vnc target"},
		{"rdp without port", device("    enable: [desktop]\n    rdp: 127.0.0.1\n"), "linux", `rdp: "127.0.0.1" is not HOST:PORT`},
		{"rdp port zero", device("    enable: [desktop]\n    rdp: 127.0.0.1:0\n"), "linux", `rdp: "127.0.0.1:0" has no port between 1 and 65535`},
		{"vnc without host", device("    enable: [desktop]\n    vnc: :5900\n"), "linux", `vnc: ":5900" is not HOST:PORT`},
		{"terminal without logins", device("    enable: [terminal]\n"), "linux", "terminal and files need at least one login"},
		{"files_root relative", device("    files_root: home/pi\n"), "linux", `files_root: "home/pi" is not an absolute path`},
		{"second document", device("") + "---\nversion: 2\ndevices: []\n", "linux", "more than one YAML document"},
		{"second document unparsable", device("") + "---\n: [\n", "linux", "more than one YAML document"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseLocal([]byte(tc.body), tc.goos)
			if !errors.Is(err, ErrInvalidLocalConfig) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want ErrInvalidLocalConfig naming %q", err, tc.want)
			}
		})
	}

	// The same capabilities pass where the rules allow them.
	for _, ok := range []struct{ name, body, goos string }{
		{"terminal and files on this machine", device("    enable: [terminal, files]\n    logins: [pi, _svc-1]\n    files_root: " + dir + "\n"), "linux"},
		{"desktop with host on windows", device("    host: 10.0.0.2\n    enable: [desktop]\n    rdp: 10.0.0.2:3389\n"), "windows"},
		{"terminal on windows with every login form", device("    enable: [terminal]\n    logins: [admin, 'CORP\\alice', bob@corp.example]\n"), "windows"},
		{"files on windows", device("    enable: [terminal, files]\n    logins: [admin]\n"), "windows"},
		{"password logins on windows", device("    enable: [terminal]\n    logins: [admin, bob@corp.example]\n    password_logins: [bob@corp.example]\n"), "windows"},
		{"bare device", device(""), "linux"},
		// An unmounted volume must not stop the devices from loading.
		{"files_root missing", device("    files_root: " + filepath.Join(dir, "missing") + "\n"), "linux"},
		{"files_root a file", device("    files_root: " + file + "\n"), "linux"},
	} {
		if _, err := parseLocal([]byte(ok.body), ok.goos); err != nil {
			t.Errorf("%s: %v", ok.name, err)
		}
	}
}

func TestWriteLocalRefusesAnInvalidConfig(t *testing.T) {
	f := userLocalConfig(t)
	ref, _ := identity.ParseDeviceRef(testIdentity)
	bad := &LocalConfig{Devices: []LocalDevice{{Identity: ref, Enable: []Capability{CapabilityDesktop}}}}
	if err := WriteLocal(f, bad, bad.Devices[0].Identity); !errors.Is(err, ErrInvalidLocalConfig) {
		t.Fatalf("WriteLocal = %v, want ErrInvalidLocalConfig", err)
	}
	if _, err := os.Stat(f.Path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("an invalid config reached disk: %v", err)
	}
}

func TestParseDesktopTargetDefaults(t *testing.T) {
	if got, err := ParseDesktopTarget("", DefaultRDPTarget); err != nil || got != "127.0.0.1:3389" {
		t.Fatalf("rdp default = %q, %v", got, err)
	}
	if got, err := ParseDesktopTarget(" ", DefaultVNCTarget); err != nil || got != "127.0.0.1:5900" {
		t.Fatalf("vnc default = %q, %v", got, err)
	}
	if got, err := ParseDesktopTarget("[fd00::5]:3390", DefaultRDPTarget); err != nil || got != "[fd00::5]:3390" {
		t.Fatalf("explicit target = %q, %v", got, err)
	}
	if _, err := ParseDesktopTarget("host", DefaultRDPTarget); err == nil {
		t.Fatal("a target without a port must be refused")
	}
}

func TestSystemLocalConfigPaths(t *testing.T) {
	for goos, want := range map[string]string{
		"linux":   filepath.Join("/etc/localport-device", "agent.yaml"),
		"freebsd": filepath.Join("/etc/localport-device", "agent.yaml"),
		"darwin":  filepath.Join("/Library/Application Support/localport-device", "agent.yaml"),
		"windows": filepath.Join(`C:\ProgramData`, "localport-device", "agent.yaml"),
	} {
		f, err := systemLocalConfig(goos, `C:\ProgramData`)
		if err != nil {
			t.Fatal(err)
		}
		if f.Path != want || f.Base != filepath.Dir(want) || f.FollowBase || !f.System {
			t.Errorf("%s: %+v, want the System file %s with its own directory as an unfollowed base", goos, f, want)
		}
	}
	if _, err := systemLocalConfig("windows", ""); err == nil {
		t.Fatal("windows without %ProgramData% must fail")
	}
}

// WriteLocal checks files_root only for the entry being changed, so an
// unmounted volume on another device never fails a write.
func TestWriteLocalChecksOnlyTheChangedFilesRoot(t *testing.T) {
	f := LocalConfigFile{Path: filepath.Join(t.TempDir(), "cfg", localConfigName)}
	f.Base = filepath.Dir(f.Path)
	unmounted := LocalDevice{
		Identity:  identity.Ref{Team: "01kpq7x2abcd34", Kind: identity.KindDevice, Identity: "tun12345.nas"},
		Enable:    []Capability{CapabilityFiles},
		Logins:    []string{"pi"},
		FilesRoot: filepath.Join(t.TempDir(), "gone"),
	}
	changed := LocalDevice{Identity: identity.Ref{Team: "01kpq7x2abcd34", Kind: identity.KindDevice, Identity: "tun12345.gw-01"}}
	cfg := &LocalConfig{Devices: []LocalDevice{unmounted, changed}}
	if err := WriteLocal(f, cfg, changed.Identity); err != nil {
		t.Fatalf("WriteLocal = %v, want the unchanged entry's files_root left unchecked", err)
	}
	if err := WriteLocal(f, cfg, unmounted.Identity); !errors.Is(err, ErrFilesRootMissing) {
		t.Fatalf("WriteLocal of the changed entry = %v, want ErrFilesRootMissing", err)
	}
}

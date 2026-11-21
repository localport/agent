package cli

import (
	"errors"
	"flag"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/identity"
)

func parseDeviceFlags(t *testing.T, args ...string) (*flag.FlagSet, *deviceFlags) {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	flags := addDeviceFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return fs, flags
}

// Flag parsing stops at the first argument that is not a flag, so anything
// after a second positional would be dropped while the token is spent.
func TestUpRefusesAnArgumentBeyondTheJoinToken(t *testing.T) {
	// A regression must not touch the real home store or config.
	t.Setenv(identity.HomeEnv, t.TempDir())
	asUnprivileged(t)
	for _, args := range [][]string{
		{"--allow-ports", "502", "lpj_x", "--host", "10.0.0.5"},
		{"lpj_x", "--enable", "files", "extra"},
	} {
		// The flags lead, so a regression that parses on stops at the
		// unroutable --api instead of a real control plane.
		withAPI := append([]string{"--api", "https://127.0.0.1:1", "--wait", "0"}, args...)
		if err := runUp("test", withAPI); !errors.Is(err, errExtraArgument) {
			t.Errorf("up %v = %v, want errExtraArgument", args, err)
		}
	}
}

// Without root a device serves only the invoking user.
func TestUnprivilegedLoginsNameOnlyTheInvokingUser(t *testing.T) {
	who := invoker{privileged: false, current: "pi", goos: "linux"}
	fs, flags := parseDeviceFlags(t, "--enable", "terminal", "--logins", "pi,root")
	var d config.LocalDevice
	if err := flags.apply(fs, &d, who); err == nil {
		t.Fatal("an unprivileged up accepted another user's login")
	}
	fs, flags = parseDeviceFlags(t, "--enable", "terminal", "--logins", "pi")
	d = config.LocalDevice{}
	if err := flags.apply(fs, &d, who); err != nil {
		t.Fatalf("own login refused: %v", err)
	}
	root := invoker{privileged: true, current: "root", goos: "linux"}
	fs, flags = parseDeviceFlags(t, "--enable", "terminal", "--logins", "pi,root")
	d = config.LocalDevice{}
	if err := flags.apply(fs, &d, root); err != nil {
		t.Fatalf("root may list any login: %v", err)
	}
}

// Logins exist only when terminal or files is enabled. The default applies
// to a merged device naming none; an empty or ungrammatical default and an
// explicit --logins without terminal or files are refused.
func TestLoginsFollowTheMergedDevice(t *testing.T) {
	apply := func(who invoker, stored config.LocalDevice, args ...string) (config.LocalDevice, error) {
		fs, flags := parseDeviceFlags(t, args...)
		err := flags.apply(fs, &stored, who)
		return stored, err
	}
	sudo := invoker{privileged: true, current: "root", sudoUser: "pi", goos: "linux"}
	if d, err := apply(sudo, config.LocalDevice{}, "--enable", "terminal"); err != nil || !slices.Equal(d.Logins, []string{"pi"}) {
		t.Fatalf("sudo default = %v, %v; want [pi]", d.Logins, err)
	}
	// The relaxed grammar accepts the names directory services produce.
	if d, err := apply(invoker{privileged: false, current: "john.doe", goos: "linux"}, config.LocalDevice{}, "--enable", "terminal"); err != nil || !slices.Equal(d.Logins, []string{"john.doe"}) {
		t.Fatalf("john.doe default = %v, %v; want [john.doe]", d.Logins, err)
	}
	if d, err := apply(invoker{privileged: false, current: "john.doe", goos: "linux"}, config.LocalDevice{}, "--allow-ports", "502"); err != nil || d.Logins != nil {
		t.Fatalf("a port-only device = %v, %v; want no logins and no refusal", d.Logins, err)
	}
	for _, who := range []invoker{
		{privileged: true, current: "root", goos: "linux"},
		{privileged: true, current: "root", sudoUser: "root", goos: "linux"},
		{privileged: false, current: "1000", goos: "linux"},
		{privileged: false, current: "", goos: "linux"},
	} {
		if _, err := apply(who, config.LocalDevice{}, "--enable", "files"); err == nil || !strings.Contains(err.Error(), "--logins") {
			t.Errorf("%+v: default = %v, want a refusal naming --logins", who, err)
		}
	}
	admin := invoker{privileged: true, current: "admin", goos: "linux"}
	if _, err := apply(admin, config.LocalDevice{}, "--enable", "desktop", "--rdp", "--logins", "pi"); !errors.Is(err, config.ErrLoginsWithoutSession) {
		t.Fatalf("--logins without terminal or files = %v, want ErrLoginsWithoutSession", err)
	}
	stored := config.LocalDevice{Enable: []config.Capability{config.CapabilityTerminal}, Logins: []string{"ops"}}
	if d, err := apply(admin, stored, "--enable", "desktop", "--rdp"); err != nil || d.Logins != nil {
		t.Fatalf("set dropping terminal = %v, %v; want the logins cleared", d.Logins, err)
	}
	if d, err := apply(admin, stored, "--allow-ports", "22"); err != nil || !slices.Equal(d.Logins, []string{"ops"}) {
		t.Fatalf("set keeping terminal = %v, %v; want the stored logins", d.Logins, err)
	}
}

// --password-logins sets the password logins, a later set keeps them, and a
// device that drops terminal and files loses them with its logins.
func TestPasswordLoginsFollowTheMergedDevice(t *testing.T) {
	admin := invoker{privileged: true, current: "admin", goos: "windows"}
	fs, flags := parseDeviceFlags(t, "--enable", "terminal", "--logins", "ops,ana@corp", "--password-logins", "ana@corp")
	var d config.LocalDevice
	if err := flags.apply(fs, &d, admin); err != nil || !slices.Equal(d.PasswordLogins, []string{"ana@corp"}) {
		t.Fatalf("--password-logins = %v, %v; want [ana@corp]", d.PasswordLogins, err)
	}
	fs, flags = parseDeviceFlags(t, "--allow-ports", "22")
	if err := flags.apply(fs, &d, admin); err != nil || !slices.Equal(d.PasswordLogins, []string{"ana@corp"}) {
		t.Fatalf("set keeping terminal = %v, %v; want the stored password logins", d.PasswordLogins, err)
	}
	fs, flags = parseDeviceFlags(t, "--enable", "desktop", "--rdp")
	if err := flags.apply(fs, &d, admin); err != nil || d.PasswordLogins != nil {
		t.Fatalf("set dropping terminal = %v, %v; want the password logins cleared", d.PasswordLogins, err)
	}
}

// terminal and files act on this machine and are refused with --host before
// any join token is spent.
func TestTerminalAndFilesAreRefusedWithAHost(t *testing.T) {
	who := invoker{privileged: false, current: "pi", goos: "linux"}
	for _, capability := range []string{"terminal", "files"} {
		fs, flags := parseDeviceFlags(t, "--enable", capability, "--host", "192.168.1.10")
		if _, err := prepareDevice(fs, flags, who); !errors.Is(err, config.ErrHostCapability) {
			t.Errorf("--enable %s --host = %v, want ErrHostCapability", capability, err)
		}
	}
	fs, flags := parseDeviceFlags(t, "--enable", "desktop", "--rdp", "--host", "192.168.1.10")
	d, err := prepareDevice(fs, flags, who)
	if err != nil {
		t.Fatalf("desktop with a host: %v", err)
	}
	if d.RDP != config.DefaultRDPTarget {
		t.Fatalf("rdp = %q, want the default target", d.RDP)
	}
}

func TestDesktopNeedsATarget(t *testing.T) {
	who := invoker{privileged: false, current: "pi", goos: "linux"}
	fs, flags := parseDeviceFlags(t, "--enable", "desktop")
	if _, err := prepareDevice(fs, flags, who); !errors.Is(err, config.ErrDesktopWithoutTarget) || !strings.Contains(err.Error(), "re-enrol without them") {
		t.Fatalf("desktop without --rdp or --vnc = %v, want ErrDesktopWithoutTarget with the re-enrol remedy", err)
	}
	root := invoker{privileged: true, current: "root", goos: "linux"}
	fs, flags = parseDeviceFlags(t, "--enable", "terminal")
	if _, err := prepareDevice(fs, flags, root); !errors.Is(err, errNoDefaultLogin) || !strings.Contains(err.Error(), "re-enrol without them") {
		t.Fatalf("terminal with no default login = %v, want errNoDefaultLogin with the re-enrol remedy", err)
	}
	fs, flags = parseDeviceFlags(t, "--enable", "desktop", "--vnc=10.0.0.5:5901")
	d, err := prepareDevice(fs, flags, who)
	if err != nil || d.VNC != "10.0.0.5:5901" {
		t.Fatalf("vnc = %q, %v", d.VNC, err)
	}
	fs, flags = parseDeviceFlags(t, "--files-root", filepath.Join(t.TempDir(), "missing"), "--enable", "files")
	if _, err := prepareDevice(fs, flags, who); err == nil {
		t.Fatal("a missing --files-root accepted")
	}
}

// A privileged process keeps credentials beside the system config and ignores
// LOCALPORT_HOME; an unprivileged one uses its own home.
func TestTheStoreFollowsThePrivilege(t *testing.T) {
	home := t.TempDir()
	t.Setenv(identity.HomeEnv, home)
	user, err := invoker{privileged: false}.store()
	if err != nil || user.Root != filepath.Join(home, "identity") {
		t.Fatalf("unprivileged store = %+v, %v", user, err)
	}
	system, err := invoker{privileged: true}.store()
	if err != nil {
		t.Fatal(err)
	}
	file, _ := config.SystemLocalConfig()
	if system.Root != filepath.Join(file.Base, "identity") || system.BaseChosen {
		t.Fatalf("privileged store = %+v, want %s/identity without following links", system, file.Base)
	}
}

// With no usable default login the refusal says why and what to pass.
func TestNoDefaultLoginNamesTheRemedy(t *testing.T) {
	for _, who := range []invoker{
		{privileged: true, current: "root", goos: "linux"},
		{privileged: false, current: "1000", goos: "linux"},
	} {
		_, err := who.defaultLogin()
		text, _ := errcode.Render(err)
		if !errors.Is(err, errNoDefaultLogin) || !strings.Contains(text, "with --logins") {
			t.Errorf("%q: Render = %q, want AG code with the --logins remedy", who.current, text)
		}
	}
}

func TestFindDevice(t *testing.T) {
	ref := func(id string) identity.Ref {
		return identity.Ref{Team: "01kpq7x2abcd34", Kind: identity.KindDevice, Identity: id}
	}
	devices := []config.LocalDevice{{Identity: ref("factory.gw-01")}, {Identity: ref("plant.gw-01")}, {Identity: ref("plant.plc-02")}}
	if i, err := findDevice(devices, "plc-02"); err != nil || i != 2 {
		t.Fatalf("plc-02 = %d, %v", i, err)
	}
	if i, err := findDevice(devices, "plant.gw-01"); err != nil || i != 1 {
		t.Fatalf("plant.gw-01 = %d, %v", i, err)
	}
	if i, err := findDevice(devices, ref("factory.gw-01").String()); err != nil || i != 0 {
		t.Fatalf("full identity = %d, %v", i, err)
	}
	if _, err := findDevice(devices, "gw-01"); !errors.Is(err, errcode.New(errcode.DeviceAmbiguous)) {
		t.Fatalf("an ambiguous name = %v, want AG118", err)
	}
	if _, err := findDevice(devices, "nope"); !errors.Is(err, errcode.New(errcode.DeviceNotFound)) {
		t.Fatalf("an unknown name = %v, want AG120", err)
	}
}

// A Windows default login comes only from a user account SID (S-1-5-21-*): a
// local account's SAM name, a domain account's UPN. Services, Entra ID and a
// failed lookup get none, with the reason and the --logins remedy.
func TestWindowsDefaultLogin(t *testing.T) {
	name := func(s string) func() (string, error) { return func() (string, error) { return s, nil } }
	fail := func() (string, error) { return "", errors.New("ERROR_NO_SUCH_DOMAIN") }
	const user = "S-1-5-21-1004336348-1177238915-682003330-1001"
	cases := []struct {
		label, sid string
		local      bool
		sam, upn   func() (string, error)
		want, hint string
	}{
		{"local account", user, true, name("ana"), fail, "ana", ""},
		{"domain account", user, false, fail, name("ana@corp.example"), "ana@corp.example", ""},
		{"domain unreachable", user, false, name("ana"), fail, "", "--password-logins"},
		{"local name unreadable", user, true, fail, name("x@y"), "", "--logins"},
		{"SYSTEM", "S-1-5-18", false, name("SYSTEM"), name("x@y"), "", "not a user account"},
		{"LOCAL SERVICE", "S-1-5-19", false, name("LOCAL SERVICE"), name("x@y"), "", "not a user account"},
		{"NETWORK SERVICE", "S-1-5-20", false, name("NETWORK SERVICE"), name("x@y"), "", "not a user account"},
		{"NT SERVICE", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", false, name("svc"), name("x@y"), "", "not a user account"},
		{"virtual account", "S-1-5-83-1-1", false, name("vm"), name("x@y"), "", "not a user account"},
		{"Entra ID", "S-1-12-1-1-2-3-4", false, name("ana"), name("ana@corp.example"), "", "--password-logins"},
	}
	for _, tc := range cases {
		login, noDefault := windowsDefaultLogin(tc.sid, tc.local, tc.sam, tc.upn)
		if login != tc.want || (tc.want == "") != (noDefault != "") || !strings.Contains(noDefault, tc.hint) {
			t.Errorf("%s: = %q, %q; want %q with a reason containing %q", tc.label, login, noDefault, tc.want, tc.hint)
		}
	}
}

// The Windows rows of the default-login table, through apply as up and set run it.
func TestWindowsLoginsThroughApply(t *testing.T) {
	apply := func(who invoker, stored config.LocalDevice, args ...string) (config.LocalDevice, error) {
		fs, flags := parseDeviceFlags(t, args...)
		err := flags.apply(fs, &stored, who)
		return stored, err
	}
	elevated := invoker{privileged: true, current: "ana@corp.example", sudoUser: "ignored", goos: "windows"}
	if d, err := apply(elevated, config.LocalDevice{}, "--enable", "terminal"); err != nil || !slices.Equal(d.Logins, []string{"ana@corp.example"}) {
		t.Fatalf("elevated default = %v, %v; want the elevated account", d.Logins, err)
	}
	plain := invoker{privileged: false, current: "ana", goos: "windows"}
	if d, err := apply(plain, config.LocalDevice{}, "--enable", "terminal"); err != nil || !slices.Equal(d.Logins, []string{"ana"}) {
		t.Fatalf("non-elevated default = %v, %v; want [ana]", d.Logins, err)
	}
	if _, err := apply(plain, config.LocalDevice{}, "--enable", "terminal", "--logins", "Ana"); err != nil {
		t.Fatalf("non-elevated --logins with its own name = %v, want accepted", err)
	}
	if _, err := apply(plain, config.LocalDevice{}, "--enable", "terminal", "--logins", "bob"); err == nil || !strings.Contains(err.Error(), "an elevated shell") {
		t.Fatalf("non-elevated --logins bob = %v, want a refusal naming an elevated shell", err)
	}
	service := invoker{privileged: true, noDefault: "this process runs as S-1-5-18, which is not a user account; name the accounts terminal and files sessions may use with --logins", goos: "windows"}
	if _, err := apply(service, config.LocalDevice{}, "--enable", "files"); !errors.Is(err, errNoDefaultLogin) || !strings.Contains(err.Error(), "S-1-5-18") {
		t.Fatalf("service account default = %v, want errNoDefaultLogin naming the SID", err)
	}
	if d, err := apply(service, config.LocalDevice{}, "--enable", "files", "--logins", "ops"); err != nil || !slices.Equal(d.Logins, []string{"ops"}) {
		t.Fatalf("service account with --logins = %v, %v; want [ops]", d.Logins, err)
	}
	entra := invoker{privileged: false, noDefault: "an Entra ID account's sign-in name cannot be read; " + windowsLoginHint, goos: "windows"}
	if _, err := apply(entra, config.LocalDevice{}, "--enable", "terminal"); !errors.Is(err, errNoDefaultLogin) || !strings.Contains(err.Error(), "--password-logins") {
		t.Fatalf("Entra default = %v, want errNoDefaultLogin naming --password-logins", err)
	}
	if _, err := apply(entra, config.LocalDevice{}, "--enable", "terminal", "--logins", "ana@corp.example"); err == nil || !strings.Contains(err.Error(), "elevated") {
		t.Fatalf("non-elevated Entra --logins = %v, want told to run elevated", err)
	}
	stored := config.LocalDevice{Enable: []config.Capability{config.CapabilityTerminal}, Logins: []string{"ops"}}
	if d, err := apply(service, stored, "--allow-ports", "22"); err != nil || !slices.Equal(d.Logins, []string{"ops"}) {
		t.Fatalf("set keeping stored logins = %v, %v", d.Logins, err)
	}
}

// The Windows account lookup runs only when the merged device uses logins and
// needs the account: for its default login or an unprivileged own-login check.
func TestWindowsLoginLookupOnlyWhenNeeded(t *testing.T) {
	for _, tc := range []struct {
		name       string
		privileged bool
		args       []string
		lookups    int
	}{
		{"privileged with logins", true, []string{"--enable", "terminal", "--logins", "ops"}, 0},
		{"unprivileged with logins", false, []string{"--enable", "terminal", "--logins", "ana@corp.example"}, 1},
		{"unprivileged without logins", false, []string{"--enable", "terminal"}, 1},
		{"no logins used", false, []string{"--allow-ports", "502"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			who := invoker{privileged: tc.privileged, goos: "windows", lookupLogin: func() (string, string) {
				calls++
				return "ana@corp.example", ""
			}}
			fs, flags := parseDeviceFlags(t, tc.args...)
			var d config.LocalDevice
			if err := flags.apply(fs, &d, who); err != nil || calls != tc.lookups {
				t.Fatalf("err %v, %d lookups; want nil, %d", err, calls, tc.lookups)
			}
		})
	}
}

// The Windows account lookup runs only when the merged device uses logins, and
// its answer is the default.
func TestWindowsLoginLookupIsDeferred(t *testing.T) {
	calls := 0
	who := invoker{privileged: true, goos: "windows", lookupLogin: func() (string, string) {
		calls++
		return "ana@corp.example", ""
	}}
	fs, flags := parseDeviceFlags(t, "--allow-ports", "502")
	var d config.LocalDevice
	if err := flags.apply(fs, &d, who); err != nil || calls != 0 {
		t.Fatalf("port-only device: err %v, %d lookups; want none", err, calls)
	}
	fs, flags = parseDeviceFlags(t, "--enable", "terminal")
	d = config.LocalDevice{}
	if err := flags.apply(fs, &d, who); err != nil || calls != 1 || !slices.Equal(d.Logins, []string{"ana@corp.example"}) {
		t.Fatalf("terminal device: %v, %v, %d lookups; want [ana@corp.example] after one", d.Logins, err, calls)
	}
}

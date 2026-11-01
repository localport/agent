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

// -t/--token is refused with the retired-token message before anything else.
// The unroutable --api keeps a regression from reaching a real control plane.
func TestConnectRefusesAFleetToken(t *testing.T) {
	// A regression must not touch the real home store or config.
	t.Setenv(identity.HomeEnv, t.TempDir())
	for _, args := range [][]string{
		{"-t", "tok", "--api", "https://127.0.0.1:1"},
		{"--token=tok", "--api", "https://127.0.0.1:1"},
		{"lpj_join", "--api", "https://127.0.0.1:1", "--wait", "0", "--token", "tok"},
	} {
		if err := runConnect("test", args); !errors.Is(err, config.ErrFleetTokenRetired) {
			t.Errorf("connect %v = %v, want ErrFleetTokenRetired", args, err)
		}
	}
}

// Flag parsing stops at the first argument that is not a flag, so anything
// after a second positional would be dropped while the token is spent.
func TestConnectRefusesAnArgumentBeyondTheJoinToken(t *testing.T) {
	// A regression must not touch the real home store or config.
	t.Setenv(identity.HomeEnv, t.TempDir())
	for _, args := range [][]string{
		{"--allow-ports", "502", "lpj_x", "--host", "10.0.0.5"},
		{"lpj_x", "--enable", "files", "extra"},
	} {
		// The flags lead, so a regression that parses on stops at the
		// unroutable --api instead of a real control plane.
		withAPI := append([]string{"--api", "https://127.0.0.1:1", "--wait", "0"}, args...)
		if err := runConnect("test", withAPI); !errors.Is(err, errExtraArgument) {
			t.Errorf("connect %v = %v, want errExtraArgument", args, err)
		}
	}
}

// Without root a device serves only the invoking user.
func TestUnprivilegedLoginsNameOnlyTheInvokingUser(t *testing.T) {
	who := invoker{privileged: false, current: "pi", goos: "linux"}
	fs, flags := parseDeviceFlags(t, "--enable", "terminal", "--logins", "pi,root")
	var d config.LocalDevice
	if err := flags.apply(fs, &d, who); err == nil {
		t.Fatal("an unprivileged connect accepted another user's login")
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
	if _, err := findDevice(devices, "gw-01"); err == nil {
		t.Fatal("an ambiguous name matched")
	}
	if _, err := findDevice(devices, "nope"); err == nil {
		t.Fatal("an unknown name matched")
	}
}

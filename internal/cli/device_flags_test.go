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
	if d, err := apply(invoker{privileged: false, current: "john.doe", goos: "linux"}, config.LocalDevice{}, "--allow-ports", "502"); err != nil || d.Logins != nil {
		t.Fatalf("a port-only device = %v, %v; want no logins and no refusal", d.Logins, err)
	}
	for _, who := range []invoker{
		{privileged: true, current: "root", goos: "linux"},
		{privileged: true, current: "root", sudoUser: "root", goos: "linux"},
		{privileged: false, current: "john.doe", goos: "linux"},
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

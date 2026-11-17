package cli

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"runtime"
	"strings"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/ports"
	"github.com/localport/agent/internal/security"
)

// invoker is who runs a command, which decides where its local config and
// credentials live.
type invoker struct {
	// privileged is root, an elevated Administrator, or `run --system` (or
	// `--service`, which implies it).
	privileged bool
	// current is the invoking account's login name, empty when it cannot be
	// looked up or, on Windows, when the account gets no default login. On
	// Windows it is in the agent's login form: a local account's bare name or a
	// domain account's UPN (windowsDefaultLogin).
	current string
	// noDefault says why the account gets no default login, set with an empty
	// current; it becomes the errNoDefaultLogin message.
	noDefault string
	// lookupLogin fills current and noDefault on Windows. It is deferred to
	// apply, the only reader, because a domain account's UPN lookup can wait on
	// an unreachable domain controller.
	lookupLogin func() (login, noDefault string)
	// sudoUser is $SUDO_USER, the account that ran sudo.
	sudoUser string
	goos     string
}

// currentInvoker describes this process. system marks it privileged
// regardless of its token, as `run --system` and `run --service` do, and so
// does running as the agent-account child (asAgentChild).
func currentInvoker(system bool) invoker {
	who := invoker{
		privileged: system || asAgentChild || privilegedProcess(),
		sudoUser:   strings.TrimSpace(os.Getenv("SUDO_USER")),
		goos:       runtime.GOOS,
	}
	if who.goos == "windows" {
		who.lookupLogin = processLogin
	} else if u, err := user.Current(); err == nil {
		who.current = u.Username
	}
	return who
}

// windowsLoginHint is the --logins form for an account whose name the agent
// cannot read: Entra ID and unreachable-domain accounts sign on with a password.
const windowsLoginHint = "name it with --logins <you@domain> --password-logins <you@domain>"

// windowsDefaultLogin is the default login of a Windows process whose token
// user is sid. Only S-1-5-21-* (local and domain user accounts) gets one: a
// local account (its token holds S-1-5-113) its bare SAM name, any other its
// UPN. Every other SID, and a name lookup that fails, gets none and a reason.
// It returns the login or, with an empty login, the reason.
func windowsDefaultLogin(sid string, local bool, samName, upn func() (string, error)) (login, noDefault string) {
	switch {
	case strings.HasPrefix(sid, "S-1-12-"):
		return "", "an Entra ID account's sign-in name cannot be read; " + windowsLoginHint
	case !strings.HasPrefix(sid, "S-1-5-21-"):
		return "", "this process runs as " + sid + ", which is not a user account; name the accounts terminal and files sessions may use with --logins"
	case local:
		name, err := samName()
		if err != nil || name == "" {
			return "", "this account's name cannot be read; name the accounts terminal and files sessions may use with --logins"
		}
		return name, ""
	}
	name, err := upn()
	if err != nil || name == "" {
		return "", "this domain account's sign-in name cannot be read (is the domain reachable?); " + windowsLoginHint
	}
	return name, ""
}

// privilegedProcess and systemLocalConfig are privileged and
// config.SystemLocalConfig; tests replace them to run a command as root
// against a temporary directory.
var (
	privilegedProcess = privileged
	systemLocalConfig = config.SystemLocalConfig
)

// localConfigFile is the system config for a privileged invoker and the
// user's own otherwise.
func (who invoker) localConfigFile() (config.LocalConfigFile, error) {
	if who.privileged {
		return systemLocalConfig()
	}
	return config.UserLocalConfig()
}

// store is the credential store beside localConfigFile: <config dir>/identity
// for a privileged invoker, the user's own store otherwise.
func (who invoker) store() (*identity.Store, error) {
	if !who.privileged {
		return identity.DefaultStore()
	}
	file, err := systemLocalConfig()
	if err != nil {
		return nil, err
	}
	return identity.SystemStore(file.Base)
}

// errNoDefaultLogin means terminal or files is enabled with no login named,
// and the invoking account gives no usable default.
var errNoDefaultLogin = errcode.New(errcode.NoDefaultLogin)

// defaultLogin is the login of a device that enables terminal or files and
// names none: $SUDO_USER when privileged on Linux or macOS and set to someone
// other than root, otherwise the invoking user. root is never a default.
func (who invoker) defaultLogin() (string, error) {
	name := who.current
	if who.goos != "windows" && who.privileged && who.sudoUser != "" && who.sudoUser != "root" {
		name = who.sudoUser
	}
	switch {
	case name == "" && who.noDefault != "":
		return "", errNoDefaultLogin.With(nil, who.noDefault)
	case name == "" || name == "root":
		return "", errNoDefaultLogin.With(nil, "this account has none; name the accounts terminal and files sessions may use with --logins")
	case !config.ValidLogin(name):
		return "", errNoDefaultLogin.With(nil, fmt.Sprintf("%q is not a valid user name; name the accounts with --logins", security.SanitizeDisplay(name)))
	}
	return name, nil
}

// deviceFlags are the capability flags `up` and `set` share.
type deviceFlags struct {
	enable, logins, passwordLogins, filesRoot, host, allowPorts *string
	rdp, vnc                                                    string
}

func addDeviceFlags(fs *flag.FlagSet) *deviceFlags {
	f := &deviceFlags{
		enable: fs.String("enable", "", "session kinds to allow: terminal, files, desktop, forwarding (comma-separated; forwarding needs terminal)"),
		logins: fs.String("logins", "", "accounts a terminal or files session may use (comma-separated)"),
		passwordLogins: fs.String("password-logins", "",
			"Windows: logins that sign on with their password, asked at each session, instead of S4U (Entra ID accounts; comma-separated, each one of --logins)"),
		filesRoot:  fs.String("files-root", "", "top of the tree a files session sees (absolute, existing directory)"),
		host:       fs.String("host", "", "where port traffic goes, for a device serving another machine (default: this machine)"),
		allowPorts: fs.String("allow-ports", "", "limit which ports this device serves, e.g. 502,80,8000-8100"),
	}
	fs.Var(desktopFlag{target: &f.rdp, def: config.DefaultRDPTarget}, "rdp",
		"RDP target for desktop sessions, --rdp or --rdp=HOST:PORT (default "+config.DefaultRDPTarget+"), --rdp=false removes it")
	fs.Var(desktopFlag{target: &f.vnc, def: config.DefaultVNCTarget}, "vnc",
		"VNC target for desktop sessions, --vnc or --vnc=HOST:PORT (default "+config.DefaultVNCTarget+"), --vnc=false removes it")
	return f
}

// apply writes every flag given on fs into d, which holds the stored entry
// (empty for a new device), and settles the logins of the merged device:
// cleared when it enables neither terminal nor files, where an explicit
// --logins is refused; defaulted when it enables one and names none. An
// unprivileged invoker may list no login but its own.
func (f *deviceFlags) apply(fs *flag.FlagSet, d *config.LocalDevice, who invoker) error {
	given := make(map[string]bool)
	fs.Visit(func(fl *flag.Flag) { given[fl.Name] = true })

	if given["enable"] {
		d.Enable = nil
		for _, c := range splitList(*f.enable) {
			d.Enable = append(d.Enable, config.Capability(c))
		}
	}
	if given["logins"] {
		d.Logins = splitList(*f.logins)
	}
	if given["password-logins"] {
		d.PasswordLogins = splitList(*f.passwordLogins)
	}
	if given["host"] {
		d.Host = strings.TrimSpace(*f.host)
	}
	if given["allow-ports"] {
		allowed, err := ports.ParseFlag(*f.allowPorts)
		if err != nil {
			return fmt.Errorf("--allow-ports: %w", err)
		}
		d.AllowPorts = allowed
	}
	if given["files-root"] {
		d.FilesRoot = strings.TrimSpace(*f.filesRoot)
	}
	if given["rdp"] {
		d.RDP = f.rdp
	}
	if given["vnc"] {
		d.VNC = f.vnc
	}
	if who.lookupLogin != nil && d.UsesLogins() {
		who.current, who.noDefault = who.lookupLogin()
	}
	if !d.UsesLogins() {
		if given["logins"] && len(d.Logins) > 0 {
			return config.ErrLoginsWithoutSession.With(nil, "--logins")
		}
		d.Logins, d.PasswordLogins = nil, nil
	} else if len(d.Logins) == 0 {
		login, err := who.defaultLogin()
		if err != nil {
			return err
		}
		d.Logins = []string{login}
	}
	if !who.privileged {
		for _, l := range d.Logins {
			if who.current == "" {
				return errcode.New(errcode.CurrentUserUnknown).With(nil, "--logins: without "+who.elevation()+" a device serves only the user running this command; run it "+who.elevated())
			}
			// Windows account names are case-insensitive.
			if l != who.current && (who.goos != "windows" || !strings.EqualFold(l, who.current)) {
				return fmt.Errorf("--logins: %q is not the user running this command; without %s a device serves only %s", l, who.elevation(), who.current)
			}
		}
	}
	return nil
}

// elevation and elevated name the privilege a command lacks, per OS.
func (who invoker) elevation() string {
	if who.goos == "windows" {
		return "an elevated shell"
	}
	return "root"
}

func (who invoker) elevated() string {
	if who.goos == "windows" {
		return "from an elevated shell"
	}
	return "with sudo"
}

func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// desktopFlag is --rdp or --vnc: given alone it sets the default target,
// =HOST:PORT sets that target, =false removes it.
type desktopFlag struct {
	target *string
	def    string
}

func (f desktopFlag) String() string {
	if f.target == nil {
		return ""
	}
	return *f.target
}

func (f desktopFlag) Set(v string) error {
	switch v {
	case "true":
		*f.target = f.def
	case "false":
		*f.target = ""
	default:
		target, err := config.ParseDesktopTarget(v, f.def)
		if err != nil {
			return err
		}
		*f.target = target
	}
	return nil
}

func (f desktopFlag) IsBoolFlag() bool { return true }

// loadLocalOrEmpty reads the local config, or returns an empty one when the
// file does not exist yet.
func loadLocalOrEmpty(file config.LocalConfigFile) (*config.LocalConfig, error) {
	cfg, err := config.LoadLocal(file)
	if errors.Is(err, fs.ErrNotExist) {
		return &config.LocalConfig{}, nil
	}
	return cfg, err
}

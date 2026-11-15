package config

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/ports"
	"github.com/localport/agent/internal/security"

	"go.yaml.in/yaml/v4"
)

// ErrHostCapability refuses terminal, files or forwarding on a device with a
// host: they act on the machine running the agent only.
var ErrHostCapability = errcode.New(errcode.HostCapability)

// ErrForwardingWithoutTerminal refuses forwarding on a device that does not
// enable terminal: forwarding rides an ssh connection.
var ErrForwardingWithoutTerminal = errcode.New(errcode.ForwardingTerminal)

// ErrLoginsWithoutSession refuses logins on a device that enables neither
// terminal nor files, the only sessions that use them.
var ErrLoginsWithoutSession = errcode.New(errcode.LoginsWithoutSession)

// ErrSessionWithoutLogins refuses terminal or files on a device that names no
// login to run them as.
var ErrSessionWithoutLogins = errcode.New(errcode.SessionWithoutLogins)

// ErrRunAsAgentLogins refuses logins on a device whose sessions run as the
// agent account.
var ErrRunAsAgentLogins = errcode.New(errcode.RunAsAgentLogins)

// ErrDesktopWithoutTarget refuses desktop on a device with no rdp or vnc
// target.
var ErrDesktopWithoutTarget = errcode.New(errcode.DesktopWithoutTarget)

// ErrFilesRootMissing means a files_root names no existing directory, as
// when its volume is not mounted.
var ErrFilesRootMissing = errcode.New(errcode.FilesRootMissing)

// ErrInvalidLocalConfig wraps every refusal of the local config's content:
// syntax, schema, version and each validation rule. The file and directory
// checks are reported on their own.
var ErrInvalidLocalConfig = errcode.New(errcode.InvalidLocalConfig)

func invalidLocal(err error) error { return ErrInvalidLocalConfig.With(err, "") }

// LocalConfigVersion is the schema version of the local device config.
const LocalConfigVersion = 2

// localConfigName is the local config's file name inside its directory.
const localConfigName = "agent.yaml"

// Capability is one session kind a device offers.
type Capability string

const (
	CapabilityTerminal Capability = "terminal"
	CapabilityFiles    Capability = "files"
	CapabilityDesktop  Capability = "desktop"
	// CapabilityForwarding allows SSH port forwarding on the device's ssh
	// connections; it needs terminal, as forwarding rides an ssh connection.
	CapabilityForwarding Capability = "forwarding"
)

// Default desktop targets, used when --rdp or --vnc is given without a value.
const (
	DefaultRDPTarget = "127.0.0.1:3389"
	DefaultVNCTarget = "127.0.0.1:5900"
)

// MaxLogins bounds the logins one device accepts.
const MaxLogins = 16

// MaxLoginLen bounds a login in bytes, as the control plane does.
const MaxLoginLen = 255

// LocalConfig is the device configuration this machine's administrator owns.
// The agent enforces it on every session; nothing from the network widens it.
type LocalConfig struct {
	Devices []LocalDevice
}

// LocalDevice is one enrolled device.
type LocalDevice struct {
	// Identity names the device credential in the identity store.
	Identity identity.Ref
	// Host is where port traffic goes. Empty means this machine.
	Host string
	// AllowPorts limits which dashboard ports are served. Nil is no limit.
	AllowPorts ports.Ceiling
	Enable     []Capability
	Logins     []string
	// PasswordLogins are the Logins (Windows only) whose sessions log on
	// with the login's password, asked by SSH keyboard-interactive after the
	// certificate, instead of S4U: Entra ID accounts and sessions that need
	// network credentials.
	PasswordLogins []string
	// FilesRoot is the top of the browsable tree. Empty means the login's home.
	FilesRoot string
	// RDP and VNC are desktop targets as HOST:PORT. Empty means none.
	RDP string
	VNC string
	// RunAsAgent runs terminal and files sessions as the agent account,
	// without PAM, for hosts with no usable login. Logins is then empty.
	RunAsAgent bool
}

// LocalConfigFile locates the local config and the private directory walk
// that guards it.
type LocalConfigFile struct {
	Path string
	// Base is where the security.CheckPrivateDir walk starts. FollowBase
	// allows Base to be a symlink: true for LOCALPORT_HOME and $HOME, false
	// for the system-wide directory.
	Base       string
	FollowBase bool
	// System marks the machine-wide device directory: it is checked and
	// written with the security system file functions (on Unix root:localport
	// 0750 directory and 0640 agent.yaml; on Windows owned by Administrators,
	// read-only to the device service) and never walked by the private
	// directory walk.
	System bool
}

// LockPath is the lock file LockLocal holds beside the config.
func (f LocalConfigFile) LockPath() string { return f.Path + ".lock" }

// SystemLocalConfig is the machine-wide config the service reads, owned by
// root (Administrator on Windows).
func SystemLocalConfig() (LocalConfigFile, error) {
	return systemLocalConfig(runtime.GOOS, os.Getenv("ProgramData"))
}

func systemLocalConfig(goos, programData string) (LocalConfigFile, error) {
	var dir string
	switch goos {
	case "windows":
		programData = strings.TrimSpace(programData)
		if programData == "" {
			return LocalConfigFile{}, errLocalUnusable.With(nil, "%ProgramData% is not set")
		}
		dir = filepath.Join(programData, security.DeviceDirName)
	case "darwin":
		dir = filepath.Join("/Library/Application Support", security.DeviceDirName)
	default:
		dir = filepath.Join("/etc", security.DeviceDirName)
	}
	return LocalConfigFile{Path: filepath.Join(dir, localConfigName), Base: dir, System: true}, nil
}

// UserLocalConfig is the config of an agent run by an unprivileged user:
// $LOCALPORT_HOME/agent.yaml, or ~/.localport/agent.yaml when LOCALPORT_HOME
// is unset, the same home the identity store uses.
func UserLocalConfig() (LocalConfigFile, error) {
	home := strings.TrimSpace(os.Getenv(identity.HomeEnv))
	if home == "" {
		userHome, err := os.UserHomeDir()
		if err != nil || userHome == "" {
			return LocalConfigFile{}, errLocalUnusable.With(nil, "no home directory to hold it; set "+identity.HomeEnv)
		}
		home = filepath.Join(userHome, ".localport")
	}
	return LocalConfigFile{Path: filepath.Join(home, localConfigName), Base: home, FollowBase: true}, nil
}

// localFile is the YAML schema of the local config.
type localFile struct {
	Version int               `yaml:"version"`
	Devices []localDeviceFile `yaml:"devices"`
}

type localDeviceFile struct {
	Identity   string   `yaml:"identity"`
	Host       string   `yaml:"host,omitempty"`
	AllowPorts string   `yaml:"allow_ports,omitempty"`
	Enable     []string `yaml:"enable,omitempty"`
	Logins     []string `yaml:"logins,omitempty"`
	// PasswordLogins is LocalDevice.PasswordLogins.
	PasswordLogins []string `yaml:"password_logins,omitempty"`
	FilesRoot      string   `yaml:"files_root,omitempty"`
	RDP            string   `yaml:"rdp,omitempty"`
	VNC            string   `yaml:"vnc,omitempty"`
	RunAsAgent     bool     `yaml:"run_as_agent,omitempty"`
}

// LoadLocal reads and validates the local config. The directory walk and the
// file read refuse a symlink, a file or directory owned by another account,
// and a file group or other can reach (on Windows, a DACL granting anyone
// else). A missing file returns an error wrapping fs.ErrNotExist.
//
// The system config (System) instead needs a root-owned directory nobody else
// can write and a root-owned regular file that group and other cannot write
// and other cannot read; the agent account reads it through its group. On
// Windows both are owned by Administrators and the device service may only
// read them (security.ReadSystemFile).
func LoadLocal(f LocalConfigFile) (*LocalConfig, error) {
	var raw []byte
	var err error
	if f.System {
		if err := security.CheckSystemDir(filepath.Dir(f.Path)); err != nil {
			return nil, errLocalUnusable.With(err, f.Path)
		}
		raw, err = security.ReadSystemFile(f.Path)
	} else {
		if err := security.CheckPrivateDir(f.Base, filepath.Dir(f.Path), f.FollowBase); err != nil {
			return nil, errLocalUnusable.With(err, f.Path)
		}
		raw, err = security.ReadPrivateFile(f.Path)
	}
	if err != nil {
		return nil, errLocalUnusable.With(err, f.Path)
	}
	return parseLocal(raw, runtime.GOOS)
}

func parseLocal(raw []byte, goos string) (*LocalConfig, error) {
	cfg, err := decodeLocal(raw, goos)
	if err != nil {
		return nil, invalidLocal(err)
	}
	return cfg, nil
}

func decodeLocal(raw []byte, goos string) (*LocalConfig, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	var lf localFile
	if err := dec.Decode(&lf); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errcode.Invalidf("local config is empty")
		}
		return nil, errcode.Invalidf("parse local config: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errcode.Invalidf("local config holds more than one YAML document")
	}
	if lf.Version != LocalConfigVersion {
		return nil, errcode.Invalidf("unsupported local config version %d: this agent reads version %d", lf.Version, LocalConfigVersion)
	}
	cfg := &LocalConfig{Devices: make([]LocalDevice, 0, len(lf.Devices))}
	for i, d := range lf.Devices {
		ref, err := identity.ParseDeviceRef(d.Identity)
		if err != nil {
			return nil, errcode.Invalidf("device %d: %w", i+1, err)
		}
		allowed, err := ports.ParseFlag(d.AllowPorts)
		if err != nil {
			return nil, errcode.Invalidf("device %s: allow_ports: %w", ref, err)
		}
		enable := make([]Capability, len(d.Enable))
		for j, c := range d.Enable {
			enable[j] = Capability(c)
		}
		cfg.Devices = append(cfg.Devices, LocalDevice{
			Identity:       ref,
			Host:           strings.TrimSpace(d.Host),
			AllowPorts:     allowed,
			Enable:         enable,
			Logins:         d.Logins,
			PasswordLogins: d.PasswordLogins,
			FilesRoot:      d.FilesRoot,
			RDP:            d.RDP,
			VNC:            d.VNC,
			RunAsAgent:     d.RunAsAgent,
		})
	}
	if err := cfg.validate(goos); err != nil {
		return nil, err
	}
	return cfg, nil
}

// WriteLocal validates cfg, checks that the files_root of the entry changed
// names an existing directory, and replaces the local config atomically,
// creating its directory owner-only when missing. Other entries' files_root
// is not checked, so an unmounted volume on another device never fails a
// write.
func WriteLocal(f LocalConfigFile, cfg *LocalConfig, changed identity.Ref) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	for _, d := range cfg.Devices {
		if d.FilesRoot == "" || d.Identity != changed {
			continue
		}
		if err := CheckFilesRoot(d.FilesRoot); err != nil {
			return fmt.Errorf("device %s: files_root: %w", d.Identity, err)
		}
	}
	raw, err := cfg.marshal()
	if err != nil {
		return err
	}
	if !f.System {
		if err := security.EnsurePrivateDir(f.Base, filepath.Dir(f.Path), f.FollowBase); err != nil {
			return errLocalUnusable.With(err, f.Path)
		}
		if err := security.WritePrivateFileAtomic(f.Path, raw); err != nil {
			return errLocalNotWritten.With(err, f.Path)
		}
		return nil
	}
	gid, err := ensureSystemDir(f)
	if err != nil {
		return err
	}
	if err := security.WriteSystemFileAtomic(f.Path, raw, gid); err != nil {
		return errLocalNotWritten.With(err, f.Path)
	}
	return nil
}

// geteuid and agentGroupID are os.Geteuid and security.AgentGroupID; tests
// replace them to act as root with their own group.
var (
	geteuid      = os.Geteuid
	agentGroupID = security.AgentGroupID
)

// ErrSystemNotRoot refuses a change to the system config directory by any
// account but root (an elevated Administrator on Windows).
var ErrSystemNotRoot = errcode.New(errcode.SystemNeedsRoot)

var (
	// errLocalUnusable is a local config that cannot be located, read,
	// secured or locked.
	errLocalUnusable = errcode.New(errcode.LocalConfigUnusable)
	// errLocalNotWritten is a failed write of the local config file.
	errLocalNotWritten = errcode.New(errcode.LocalConfigNotWritten)
)

// systemWriter reports whether this process owns the system files: root, or
// an elevated Administrator on Windows.
func systemWriter() bool { return security.IsSystemWriter(geteuid()) }

// ensureSystemDir creates or secures the system config directory as
// root:localport 0750 and returns the group's gid. A missing group is
// security.ErrAgentGroupMissing, whose message names the install command.
func ensureSystemDir(f LocalConfigFile) (int, error) {
	if !systemWriter() {
		return 0, ErrSystemNotRoot.With(nil, f.Path)
	}
	gid, err := agentGroupID()
	if err != nil {
		return 0, err
	}
	if err := security.EnsureSystemDir(filepath.Dir(f.Path), gid); err != nil {
		return 0, errLocalUnusable.With(err, f.Path)
	}
	return gid, nil
}

// EnsureSystemRunLock creates or secures the system config directory and its
// run.lock (root:localport 0660), so the agent account can lock it. Root
// only; install and connect run it before the agent service starts.
func EnsureSystemRunLock(f LocalConfigFile) error {
	lock, err := openLock(f, f.RunLockPath())
	if err != nil {
		return err
	}
	return lock.Close()
}

func (c *LocalConfig) marshal() ([]byte, error) {
	lf := localFile{Version: LocalConfigVersion, Devices: make([]localDeviceFile, len(c.Devices))}
	for i, d := range c.Devices {
		enable := make([]string, len(d.Enable))
		for j, c := range d.Enable {
			enable[j] = string(c)
		}
		lf.Devices[i] = localDeviceFile{
			Identity:       d.Identity.String(),
			Host:           d.Host,
			AllowPorts:     d.AllowPorts.String(),
			Enable:         enable,
			Logins:         d.Logins,
			PasswordLogins: d.PasswordLogins,
			FilesRoot:      d.FilesRoot,
			RDP:            d.RDP,
			VNC:            d.VNC,
			RunAsAgent:     d.RunAsAgent,
		}
	}
	raw, err := yaml.Marshal(&lf)
	if err != nil {
		return nil, fmt.Errorf("encode local config: %w", err)
	}
	return raw, nil
}

// Validate applies the rules LoadLocal and WriteLocal enforce, for this
// machine's operating system.
// Refusals wrap ErrInvalidLocalConfig.
func (c *LocalConfig) Validate() error {
	if err := c.validate(runtime.GOOS); err != nil {
		return invalidLocal(err)
	}
	return nil
}

func (c *LocalConfig) validate(goos string) error {
	if len(c.Devices) == 0 {
		return errcode.Invalidf("local config lists no devices")
	}
	seen := make(map[identity.Ref]struct{}, len(c.Devices))
	for _, d := range c.Devices {
		if _, dup := seen[d.Identity]; dup {
			return errcode.Invalidf("device %s is listed twice", d.Identity)
		}
		seen[d.Identity] = struct{}{}
		if err := d.validate(goos); err != nil {
			return err
		}
	}
	return nil
}

// Validate applies the per-device rules, for this machine's operating system.
// Refusals wrap ErrInvalidLocalConfig.
func (d LocalDevice) Validate() error {
	if err := d.validate(runtime.GOOS); err != nil {
		return invalidLocal(err)
	}
	return nil
}

func (d LocalDevice) validate(goos string) error {
	name := d.Identity.String()
	if _, err := identity.ParseDeviceRef(name); err != nil {
		return err
	}
	return d.validateSettings(name, goos)
}

// ValidateSettings applies the per-device rules other than the identity, for
// this machine's operating system: what `connect` checks before it spends a
// join token. Refusals wrap ErrInvalidLocalConfig.
func (d LocalDevice) ValidateSettings() error {
	if err := d.validateSettings("this device", runtime.GOOS); err != nil {
		return invalidLocal(err)
	}
	return nil
}

func (d LocalDevice) validateSettings(name, goos string) error {
	if d.Host != "" {
		if _, err := parseDeviceHost(name, d.Host); err != nil {
			return err
		}
	}
	device := "device " + name
	if err := validLogins(d.Logins); err != nil {
		return errcode.Invalidf("%s: %w", device, err)
	}
	for i, c := range d.Enable {
		switch c {
		case CapabilityTerminal, CapabilityFiles, CapabilityDesktop, CapabilityForwarding:
		default:
			return errcode.Invalidf("%s: enable %q is not one of terminal, files, desktop, forwarding", device, security.SanitizeDisplay(string(c)))
		}
		if slices.Contains(d.Enable[:i], c) {
			return errcode.Invalidf("%s: enable lists %s twice", device, c)
		}
		// Terminal, files and forwarding act on the machine running the agent.
		if (c == CapabilityTerminal || c == CapabilityFiles || c == CapabilityForwarding) && d.Host != "" {
			return ErrHostCapability.With(nil, device+": "+string(c))
		}
	}
	if slices.Contains(d.Enable, CapabilityForwarding) && !slices.Contains(d.Enable, CapabilityTerminal) {
		return ErrForwardingWithoutTerminal.With(nil, device)
	}
	if err := validPasswordLogins(d, goos); err != nil {
		return errcode.Invalidf("%s: %w", device, err)
	}
	if len(d.Logins) > 0 && !d.UsesLogins() {
		return ErrLoginsWithoutSession.With(nil, device)
	}
	if d.RunAsAgent && len(d.Logins) > 0 {
		return ErrRunAsAgentLogins.With(nil, device)
	}
	if len(d.Logins) == 0 && d.UsesLogins() && !d.RunAsAgent {
		return ErrSessionWithoutLogins.With(nil, device)
	}
	if slices.Contains(d.Enable, CapabilityDesktop) && d.RDP == "" && d.VNC == "" {
		return ErrDesktopWithoutTarget.With(nil, device)
	}
	for _, target := range []struct{ key, value string }{{"rdp", d.RDP}, {"vnc", d.VNC}} {
		if target.value == "" {
			continue
		}
		if err := validDesktopTarget(target.value); err != nil {
			return errcode.Invalidf("%s: %s: %w", device, target.key, err)
		}
	}
	// Existence is checked on write and at session time, not here, so an
	// unmounted volume never stops the devices from loading.
	if d.FilesRoot != "" && !filepath.IsAbs(d.FilesRoot) {
		return errcode.Invalidf("%s: files_root: \"%s\" is not an absolute path", device, security.SanitizeDisplay(d.FilesRoot))
	}
	return nil
}

// Equal reports whether d and o hold the same settings.
func (d LocalDevice) Equal(o LocalDevice) bool {
	return d.Identity == o.Identity && d.Host == o.Host && d.AllowPorts.String() == o.AllowPorts.String() &&
		slices.Equal(d.Enable, o.Enable) && slices.Equal(d.Logins, o.Logins) &&
		slices.Equal(d.PasswordLogins, o.PasswordLogins) && d.FilesRoot == o.FilesRoot && d.RDP == o.RDP && d.VNC == o.VNC && d.RunAsAgent == o.RunAsAgent
}

// UsesLogins reports whether d enables a session kind that runs as a login:
// terminal or files.
func (d LocalDevice) UsesLogins() bool {
	return slices.Contains(d.Enable, CapabilityTerminal) || slices.Contains(d.Enable, CapabilityFiles)
}

// ValidLogin reports whether name follows the login grammar the control plane
// also enforces: systemd's relaxed user-name rule (systemd.io/USER_NAMES;
// user-util.c valid_user_group_name with VALID_USER_RELAX): not empty, valid
// UTF-8, no control character, no ':' or '/', no leading or trailing space, not
// all digits, not '-' followed only by digits, not "." or "..". It also refuses
// ',', the --logins separator, and bounds the length. Whether the account
// exists is the host's lookup to decide.
func ValidLogin(name string) bool {
	if name == "" || len(name) > MaxLoginLen || !utf8.ValidString(name) ||
		name == "." || name == ".." || name[0] == ' ' || name[len(name)-1] == ' ' ||
		strings.ContainsAny(name, ":/,") || strings.Trim(strings.TrimPrefix(name, "-"), "0123456789") == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] < ' ' || name[i] == 0x7f {
			return false
		}
	}
	return true
}

// validPasswordLogins checks password_logins: Windows only, each one of the
// device's logins and listed once.
func validPasswordLogins(d LocalDevice, goos string) error {
	if len(d.PasswordLogins) == 0 {
		return nil
	}
	if goos != "windows" {
		return errcode.Invalidf("password_logins is available on Windows only")
	}
	for i, l := range d.PasswordLogins {
		if !slices.Contains(d.Logins, l) {
			return errcode.Invalidf("password login %q is not one of logins", security.SanitizeDisplay(l))
		}
		if slices.Contains(d.PasswordLogins[:i], l) {
			return errcode.Invalidf("password login %q is listed twice", security.SanitizeDisplay(l))
		}
	}
	return nil
}

func validLogins(logins []string) error {
	if len(logins) > MaxLogins {
		return errcode.Invalidf("%d logins, over the limit of %d", len(logins), MaxLogins)
	}
	for i, l := range logins {
		if !ValidLogin(l) {
			return errcode.Invalidf("login %q is not a valid user name (no ':', '/', ',' or control characters, not all digits, no leading or trailing space, at most %d bytes)", security.SanitizeDisplay(l), MaxLoginLen)
		}
		if slices.Contains(logins[:i], l) {
			return errcode.Invalidf("login %q is listed twice", security.SanitizeDisplay(l))
		}
	}
	return nil
}

// ParseDesktopTarget reads an --rdp or --vnc value: HOST:PORT, or def when
// value is empty.
func ParseDesktopTarget(value, def string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return def, nil
	}
	if err := validDesktopTarget(value); err != nil {
		return "", err
	}
	return value, nil
}

func validDesktopTarget(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return errcode.Invalidf("%q is not HOST:PORT", security.SanitizeDisplay(value))
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return errcode.Invalidf("%q has no port between 1 and 65535", security.SanitizeDisplay(value))
	}
	return nil
}

// localLockWait bounds how long LockLocal waits for another writer.
const localLockWait = 2 * time.Minute

// LockLocal takes the local config's write lock, agent.yaml.lock beside it,
// creating the directory owner-only when missing (for the system config, root
// only, see openLock). set holds it across its
// read-modify-write, and connect from its re-read after enrolment to its
// write, so neither drops the other's entry. It waits up to localLockWait.
// A process that also holds run.lock takes run.lock first (see LockRun).
func LockLocal(f LocalConfigFile) (release func(), err error) {
	lock, held, err := lockBeside(context.Background(), f, f.LockPath(), localLockWait)
	if err != nil {
		return nil, errLocalUnusable.With(err, "lock "+f.Path)
	}
	if !held {
		return nil, errcode.New(errcode.LocalConfigBusy).With(nil, f.Path)
	}
	return func() { _ = unlockAndClose(lock) }, nil
}

// ErrRunLocked means another process holds run.lock: a privileged run, connect
// --foreground or service uninstall --purge on this config's devices.
var ErrRunLocked = errcode.New(errcode.RunLocked)

// RunLockPath is the lock file LockRun holds in the config directory.
func (f LocalConfigFile) RunLockPath() string {
	return filepath.Join(filepath.Dir(f.Path), "run.lock")
}

// LockRun takes the exclusive run.lock of the config directory, creating the
// directory owner-only when missing (for the system config, root creates both
// and the agent account opens the existing run.lock), so only one process
// serves the devices
// of a config. It waits up to wait (zero tries once) and then returns
// ErrRunLocked. The holder records its PID in the file (RunLockHolder). The
// lock file is opened close-on-exec (not inheritable on Windows), so session
// children never hold it. release unlocks, then closes the file; the holder
// calls it before it exits. Lock order: run.lock before agent.yaml.lock; a
// process holding agent.yaml.lock only tries run.lock.
func LockRun(f LocalConfigFile, wait time.Duration) (release func() error, err error) {
	return LockRunContext(context.Background(), f, wait)
}

// LockRunContext is LockRun with a wait that also ends, with ctx's error,
// when ctx ends.
func LockRunContext(ctx context.Context, f LocalConfigFile, wait time.Duration) (release func() error, err error) {
	path := f.RunLockPath()
	lock, held, err := lockBeside(ctx, f, path, wait)
	if err != nil {
		return nil, errLocalUnusable.With(err, "lock "+path)
	}
	if !held {
		return nil, ErrRunLocked.With(nil, path+" is held")
	}
	if err := recordHolder(lock); err != nil {
		return nil, errors.Join(errLocalUnusable.With(err, "record the holder of "+path), unlockAndClose(lock))
	}
	// The record is cleared while the lock is still held, so the next holder
	// never shows this PID before it records its own. A holder that dies
	// leaves its PID, which no manager reports as a running service.
	return func() error { return errors.Join(lock.Truncate(0), unlockAndClose(lock)) }, nil
}

// runLockPIDOffset is where the holder writes its PID. Byte 0 is the range
// LockFileEx locks on Windows, which no other process can read.
const runLockPIDOffset = 1

func recordHolder(lock *os.File) error {
	if err := lock.Truncate(0); err != nil {
		return err
	}
	_, err := lock.WriteAt([]byte("\n"+strconv.Itoa(os.Getpid())+"\n"), 0)
	return err
}

// RunLockHolder returns the PID the holder of run.lock recorded, or 0 when
// none is recorded yet. Callers read it only while LockRun fails, because a
// holder that died without releasing leaves its PID behind.
func RunLockHolder(f LocalConfigFile) (int, error) {
	file, err := os.Open(f.RunLockPath())
	if err != nil {
		return 0, err
	}
	defer file.Close()
	buf := make([]byte, 24)
	n, err := file.ReadAt(buf, runLockPIDOffset)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, errLocalUnusable.With(err, "read "+f.RunLockPath())
	}
	text := strings.TrimSpace(string(buf[:n]))
	if text == "" {
		return 0, nil
	}
	pid, err := strconv.Atoi(text)
	if err != nil || pid <= 0 {
		return 0, errLocalUnusable.With(nil, fmt.Sprintf("%s records no valid PID: %q", f.RunLockPath(), text))
	}
	return pid, nil
}

// lockPoll is how often a lock wait retries; flock and LockFileEx have no
// bounded blocking form.
const lockPoll = 200 * time.Millisecond

// lockBeside opens path, a lock file in the config directory, and locks it
// exclusively, retrying for up to wait or until ctx ends. held is false when
// another process still holds the lock at the deadline; the file is then
// closed.
func lockBeside(ctx context.Context, f LocalConfigFile, path string, wait time.Duration) (lock *os.File, held bool, err error) {
	lock, err = openLock(f, path)
	if err != nil {
		return nil, false, err
	}
	deadline := time.Now().Add(wait)
	for {
		held, err := security.TryLockFile(lock)
		if err != nil {
			lock.Close()
			return nil, false, err
		}
		if held {
			return lock, true, nil
		}
		if !time.Now().Before(deadline) {
			lock.Close()
			return nil, false, nil
		}
		select {
		case <-ctx.Done():
			lock.Close()
			return nil, false, ctx.Err()
		case <-time.After(lockPoll):
		}
	}
}

// openLock opens the lock file path beside the config. For the system config,
// root (an elevated Administrator on Windows) creates or secures the
// directory and the lock (run.lock root:localport 0660, agent.yaml.lock 0600;
// on Windows the matching DACLs); any other account only checks the
// directory and opens the existing run.lock.
func openLock(f LocalConfigFile, path string) (*os.File, error) {
	if !f.System {
		if err := security.EnsurePrivateDir(f.Base, filepath.Dir(f.Path), f.FollowBase); err != nil {
			return nil, errLocalUnusable.With(err, f.Path)
		}
		return security.OpenLockFile(path)
	}
	runLock := path == f.RunLockPath()
	if systemWriter() {
		gid, err := ensureSystemDir(f)
		if err != nil {
			return nil, err
		}
		perm := security.SystemConfigLockPerm
		if runLock {
			perm = security.SystemRunLockPerm
		}
		return security.OpenSystemLock(path, gid, perm)
	}
	if !runLock {
		return nil, ErrSystemNotRoot.With(nil, f.Path)
	}
	if err := security.CheckSystemDir(filepath.Dir(f.Path)); err != nil {
		return nil, errLocalUnusable.With(err, f.Path)
	}
	return security.OpenSystemRunLock(path)
}

func unlockAndClose(lock *os.File) error {
	return errors.Join(security.UnlockFile(lock), lock.Close())
}

// CheckFilesRoot requires an absolute path naming an existing directory.
// WriteLocal runs it; loading checks only that the path is absolute.
func CheckFilesRoot(path string) error {
	shown := security.SanitizeDisplay(path)
	if !filepath.IsAbs(path) {
		return errcode.Invalidf("\"%s\" is not an absolute path", shown)
	}
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return ErrFilesRootMissing.With(nil, fmt.Sprintf("\"%s\" does not exist", shown))
	}
	if err != nil {
		// The PathError would repeat the unsanitized path.
		var pathErr *fs.PathError
		if errors.As(err, &pathErr) {
			err = pathErr.Err
		}
		return ErrFilesRootMissing.With(err, fmt.Sprintf("inspect \"%s\"", shown))
	}
	if !info.IsDir() {
		return ErrFilesRootMissing.With(nil, fmt.Sprintf("\"%s\" is not a directory", shown))
	}
	return nil
}

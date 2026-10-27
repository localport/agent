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
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/ports"
	"github.com/localport/agent/internal/security"

	"go.yaml.in/yaml/v4"
)

// ErrFleetTokenRetired refuses a shared fleet token wherever one is offered.
// Every device enrols with its own credential.
var ErrFleetTokenRetired = errcode.New(errcode.FleetTokenRetired)

// ErrHostCapability refuses terminal or files on a device with a host: they
// act on the machine running the agent only.
var ErrHostCapability = errcode.New(errcode.HostCapability)

// ErrLoginsWithoutSession refuses logins on a device that enables neither
// terminal nor files, the only sessions that use them.
var ErrLoginsWithoutSession = errcode.New(errcode.LoginsWithoutSession)

// ErrSessionWithoutLogins refuses terminal or files on a device that names no
// login to run them as.
var ErrSessionWithoutLogins = errcode.New(errcode.SessionWithoutLogins)

// ErrDesktopWithoutTarget refuses desktop on a device with no rdp or vnc
// target.
var ErrDesktopWithoutTarget = errcode.New(errcode.DesktopWithoutTarget)

// ErrFilesRootMissing means a files_root names no existing directory, as
// when its volume is not mounted.
var ErrFilesRootMissing = errcode.New(errcode.FilesRootMissing)

// ErrInvalidLocalConfig wraps every refusal of the local config's content:
// syntax, schema, version and each validation rule. ErrFleetTokenRetired and
// the file and directory checks are reported on their own.
var ErrInvalidLocalConfig = errcode.New(errcode.InvalidLocalConfig)

func invalidLocal(err error) error { return fmt.Errorf("%w: %w", ErrInvalidLocalConfig, err) }

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
)

// Default desktop targets, used when --rdp or --vnc is given without a value.
const (
	DefaultRDPTarget = "127.0.0.1:3389"
	DefaultVNCTarget = "127.0.0.1:5900"
)

// MaxLogins bounds the logins one device accepts.
const MaxLogins = 16

// loginPattern is the portable POSIX login grammar the control plane also
// enforces on agent-reported logins.
var loginPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

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
	// FilesRoot is the top of the browsable tree. Empty means the login's home.
	FilesRoot string
	// RDP and VNC are desktop targets as HOST:PORT. Empty means none.
	RDP string
	VNC string
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
			return LocalConfigFile{}, errors.New("locate the local config: %ProgramData% is not set")
		}
		dir = filepath.Join(programData, security.DeviceDirName)
	case "darwin":
		dir = filepath.Join("/Library/Application Support", security.DeviceDirName)
	default:
		dir = filepath.Join("/etc", security.DeviceDirName)
	}
	return LocalConfigFile{Path: filepath.Join(dir, localConfigName), Base: dir}, nil
}

// UserLocalConfig is the config of an agent run by an unprivileged user:
// $LOCALPORT_HOME/agent.yaml, or ~/.localport/agent.yaml when LOCALPORT_HOME
// is unset, the same home the identity store uses.
func UserLocalConfig() (LocalConfigFile, error) {
	home := strings.TrimSpace(os.Getenv(identity.HomeEnv))
	if home == "" {
		userHome, err := os.UserHomeDir()
		if err != nil || userHome == "" {
			return LocalConfigFile{}, fmt.Errorf("locate the local config: no home directory (set %s)", identity.HomeEnv)
		}
		home = filepath.Join(userHome, ".localport")
	}
	return LocalConfigFile{Path: filepath.Join(home, localConfigName), Base: home, FollowBase: true}, nil
}

// localFile is the YAML schema of the local config. Fleets is decoded, in any
// shape, only to refuse it with ErrFleetTokenRetired rather than as an
// unknown key.
type localFile struct {
	Version int               `yaml:"version"`
	Devices []localDeviceFile `yaml:"devices"`
	Fleets  yaml.Node         `yaml:"fleets,omitempty"`
}

type localDeviceFile struct {
	Identity   string   `yaml:"identity"`
	Host       string   `yaml:"host,omitempty"`
	AllowPorts string   `yaml:"allow_ports,omitempty"`
	Enable     []string `yaml:"enable,omitempty"`
	Logins     []string `yaml:"logins,omitempty"`
	FilesRoot  string   `yaml:"files_root,omitempty"`
	RDP        string   `yaml:"rdp,omitempty"`
	VNC        string   `yaml:"vnc,omitempty"`
}

// LoadLocal reads and validates the local config. The directory walk and the
// file read refuse a symlink, a file or directory owned by another account,
// and a file group or other can reach (on Windows, a DACL granting anyone
// else). A missing file returns an error wrapping fs.ErrNotExist.
func LoadLocal(f LocalConfigFile) (*LocalConfig, error) {
	if err := security.CheckPrivateDir(f.Base, filepath.Dir(f.Path), f.FollowBase); err != nil {
		return nil, fmt.Errorf("local config %s: %w", f.Path, err)
	}
	raw, err := security.ReadPrivateFile(f.Path)
	if err != nil {
		return nil, fmt.Errorf("local config: %w", err)
	}
	return parseLocal(raw, runtime.GOOS)
}

func parseLocal(raw []byte, goos string) (*LocalConfig, error) {
	cfg, err := decodeLocal(raw, goos)
	if err != nil && !errors.Is(err, ErrFleetTokenRetired) {
		return nil, invalidLocal(err)
	}
	return cfg, err
}

func decodeLocal(raw []byte, goos string) (*LocalConfig, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	var lf localFile
	if err := dec.Decode(&lf); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("local config is empty")
		}
		return nil, fmt.Errorf("parse local config: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("local config holds more than one YAML document")
	}
	if lf.Fleets.Kind != 0 {
		return nil, ErrFleetTokenRetired
	}
	if lf.Version != LocalConfigVersion {
		return nil, fmt.Errorf("unsupported local config version %d: this agent reads version %d", lf.Version, LocalConfigVersion)
	}
	cfg := &LocalConfig{Devices: make([]LocalDevice, 0, len(lf.Devices))}
	for i, d := range lf.Devices {
		ref, err := identity.ParseDeviceRef(d.Identity)
		if err != nil {
			return nil, fmt.Errorf("device %d: %w", i+1, err)
		}
		allowed, err := ports.ParseFlag(d.AllowPorts)
		if err != nil {
			return nil, fmt.Errorf("device %s: allow_ports: %w", ref, err)
		}
		enable := make([]Capability, len(d.Enable))
		for j, c := range d.Enable {
			enable[j] = Capability(c)
		}
		cfg.Devices = append(cfg.Devices, LocalDevice{
			Identity:   ref,
			Host:       strings.TrimSpace(d.Host),
			AllowPorts: allowed,
			Enable:     enable,
			Logins:     d.Logins,
			FilesRoot:  d.FilesRoot,
			RDP:        d.RDP,
			VNC:        d.VNC,
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
	if err := security.EnsurePrivateDir(f.Base, filepath.Dir(f.Path), f.FollowBase); err != nil {
		return fmt.Errorf("local config %s: %w", f.Path, err)
	}
	return security.WritePrivateFileAtomic(f.Path, raw)
}

func (c *LocalConfig) marshal() ([]byte, error) {
	lf := localFile{Version: LocalConfigVersion, Devices: make([]localDeviceFile, len(c.Devices))}
	for i, d := range c.Devices {
		enable := make([]string, len(d.Enable))
		for j, c := range d.Enable {
			enable[j] = string(c)
		}
		lf.Devices[i] = localDeviceFile{
			Identity:   d.Identity.String(),
			Host:       d.Host,
			AllowPorts: d.AllowPorts.String(),
			Enable:     enable,
			Logins:     d.Logins,
			FilesRoot:  d.FilesRoot,
			RDP:        d.RDP,
			VNC:        d.VNC,
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
		return errors.New("local config lists no devices")
	}
	seen := make(map[identity.Ref]struct{}, len(c.Devices))
	for _, d := range c.Devices {
		if _, dup := seen[d.Identity]; dup {
			return fmt.Errorf("device %s is listed twice", d.Identity)
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
	if err := validLogins(d.Logins); err != nil {
		return fmt.Errorf("device %s: %w", name, err)
	}
	for i, c := range d.Enable {
		switch c {
		case CapabilityTerminal, CapabilityFiles, CapabilityDesktop:
		default:
			return fmt.Errorf("device %s: enable %q is not one of terminal, files, desktop", name, c)
		}
		if slices.Contains(d.Enable[:i], c) {
			return fmt.Errorf("device %s: enable lists %s twice", name, c)
		}
		// Terminal and files act on the machine running the agent.
		if c == CapabilityTerminal || c == CapabilityFiles {
			if d.Host != "" {
				return fmt.Errorf("device %s: %s: %w", name, c, ErrHostCapability)
			}
			if goos == "windows" {
				return fmt.Errorf("device %s: %s is not available on Windows", name, c)
			}
		}
	}
	if len(d.Logins) > 0 && !d.UsesLogins() {
		return fmt.Errorf("device %s: %w", name, ErrLoginsWithoutSession)
	}
	if len(d.Logins) == 0 && d.UsesLogins() {
		return fmt.Errorf("device %s: %w", name, ErrSessionWithoutLogins)
	}
	if slices.Contains(d.Enable, CapabilityDesktop) && d.RDP == "" && d.VNC == "" {
		return fmt.Errorf("device %s: %w", name, ErrDesktopWithoutTarget)
	}
	for _, target := range []struct{ key, value string }{{"rdp", d.RDP}, {"vnc", d.VNC}} {
		if target.value == "" {
			continue
		}
		if err := validDesktopTarget(target.value); err != nil {
			return fmt.Errorf("device %s: %s: %w", name, target.key, err)
		}
	}
	// Existence is checked on write and at session time, not here, so an
	// unmounted volume never stops the devices from loading.
	if d.FilesRoot != "" && !filepath.IsAbs(d.FilesRoot) {
		return fmt.Errorf("device %s: files_root: %q is not an absolute path", name, security.SanitizeDisplay(d.FilesRoot))
	}
	return nil
}

// Equal reports whether d and o hold the same settings.
func (d LocalDevice) Equal(o LocalDevice) bool {
	return d.Identity == o.Identity && d.Host == o.Host && d.AllowPorts.String() == o.AllowPorts.String() &&
		slices.Equal(d.Enable, o.Enable) && slices.Equal(d.Logins, o.Logins) &&
		d.FilesRoot == o.FilesRoot && d.RDP == o.RDP && d.VNC == o.VNC
}

// UsesLogins reports whether d enables a session kind that runs as a login:
// terminal or files.
func (d LocalDevice) UsesLogins() bool {
	return slices.Contains(d.Enable, CapabilityTerminal) || slices.Contains(d.Enable, CapabilityFiles)
}

// ValidLogin reports whether name follows the login grammar the control plane
// also enforces.
func ValidLogin(name string) bool { return loginPattern.MatchString(name) }

func validLogins(logins []string) error {
	if len(logins) > MaxLogins {
		return fmt.Errorf("%d logins, over the limit of %d", len(logins), MaxLogins)
	}
	for i, l := range logins {
		if !loginPattern.MatchString(l) {
			return fmt.Errorf("login %q is not a valid user name (lowercase letters, digits, _ and -, starting with a letter or _, at most 32 characters)", security.SanitizeDisplay(l))
		}
		if slices.Contains(logins[:i], l) {
			return fmt.Errorf("login %q is listed twice", l)
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
		return fmt.Errorf("%q is not HOST:PORT", security.SanitizeDisplay(value))
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%q has no port between 1 and 65535", security.SanitizeDisplay(value))
	}
	return nil
}

// localLockWait bounds how long LockLocal waits for another writer.
const localLockWait = 2 * time.Minute

// LockLocal takes the local config's write lock, agent.yaml.lock beside it,
// creating the directory owner-only when missing. set holds it across its
// read-modify-write, and connect from its re-read after enrolment to its
// write, so neither drops the other's entry. It waits up to localLockWait.
// A process that also holds run.lock takes run.lock first (see LockRun).
func LockLocal(f LocalConfigFile) (release func(), err error) {
	lock, held, err := lockBeside(context.Background(), f, f.LockPath(), localLockWait)
	if err != nil {
		return nil, fmt.Errorf("lock local config: %w", err)
	}
	if !held {
		return nil, fmt.Errorf("local config %s: another localport command is still changing it", f.Path)
	}
	return func() { _ = unlockAndClose(lock) }, nil
}

// lockPoll is how often a lock wait retries; flock and LockFileEx have no
// bounded blocking form.
const lockPoll = 200 * time.Millisecond

// lockBeside opens path, a lock file in the config directory, and locks it
// exclusively, retrying for up to wait or until ctx ends. held is false when
// another process still holds the lock at the deadline; the file is then
// closed.
func lockBeside(ctx context.Context, f LocalConfigFile, path string, wait time.Duration) (lock *os.File, held bool, err error) {
	if err := security.EnsurePrivateDir(f.Base, filepath.Dir(f.Path), f.FollowBase); err != nil {
		return nil, false, fmt.Errorf("local config %s: %w", f.Path, err)
	}
	lock, err = security.OpenLockFile(path)
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

func unlockAndClose(lock *os.File) error {
	return errors.Join(security.UnlockFile(lock), lock.Close())
}

// CheckFilesRoot requires an absolute path naming an existing directory.
// WriteLocal runs it; loading checks only that the path is absolute.
func CheckFilesRoot(path string) error {
	shown := security.SanitizeDisplay(path)
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%q is not an absolute path", shown)
	}
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%q does not exist: %w: %w", shown, ErrFilesRootMissing, fs.ErrNotExist)
	}
	if err != nil {
		// The PathError would repeat the unsanitized path.
		var pathErr *fs.PathError
		if errors.As(err, &pathErr) {
			err = pathErr.Err
		}
		return fmt.Errorf("inspect %q: %w", shown, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory: %w", shown, ErrFilesRootMissing)
	}
	return nil
}

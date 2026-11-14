package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/localport/agent/internal/agent"
	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/security"
	"github.com/localport/agent/internal/service"
	"github.com/localport/agent/internal/ui"
)

// runConnect enrols this machine as a fleet device with a single-use join
// token and records it in the local config. As root or an elevated
// Administrator it then installs and starts the device service, unless
// --foreground; otherwise it runs the device in the foreground. With --config
// it runs every tunnel in a config file. A run that installs the service runs
// to the end through a hangup of its terminal and records its outcome in the
// system log.
func runConnect(version string, args []string) (retErr error) {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		configPath  = fs.String("config", "", "path to a YAML config of tunnels")
		apiURL      = fs.String("api", "", "control plane base URL (default "+identity.DefaultAPIURL+")")
		wait        = fs.Duration("wait", identity.DefaultRetryBudget, "how long to keep retrying while the control plane is unreachable (0 = one attempt)")
		noUI        = fs.Bool("noui", false, "disable the live view and emit plain logs (auto-enabled when stderr is not a TTY)")
		noMux       = fs.Bool("no-mux", false, "send each inbound connection over its own connection instead of multiplexing them; a device then serves no browser or CLI sessions; as Administrator on Windows only with --foreground or --config, as root on Linux and macOS only with --config")
		noInspect   = fs.Bool("no-inspect", false, "do not inspect HTTP requests (--config)")
		logRequests = fs.Bool("log-requests", false, "log one line per HTTP request in headless mode (--config)")
		foreground  = fs.Bool("foreground", false, "run the device in this terminal instead of installing the service (root or Administrator); as root on Linux and macOS it runs every device in the machine-wide config")
	)
	device := addDeviceFlags(fs)
	fs.Usage = func() { usageConnect(fs) }

	// The join token is a leading positional, as the dashboard shows it.
	joinToken, rest := "", args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		joinToken, rest = args[0], args[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	positional := fs.Args()
	if joinToken == "" && len(positional) > 0 {
		joinToken, positional = positional[0], positional[1:]
	}
	// Flag parsing stops at the first non-flag, so a flag after a join token
	// that follows flags would be dropped while the token is spent.
	if len(positional) > 0 {
		fs.Usage()
		return errExtraArgument.With(nil, fmt.Sprintf("%q; put every flag before the join token or right after it", security.SanitizeDisplay(positional[0])))
	}

	if *configPath != "" {
		if joinToken != "" {
			return errors.New("a join token cannot be combined with --config")
		}
		if err := refuseBesideConfig(fs, *configPath, "enable", "logins", "files-root", "host", "allow-ports", "rdp", "vnc", "api", "wait", "foreground"); err != nil {
			return err
		}
		return runConfigFile(version, *configPath, *noUI, *noMux, *noInspect, *logRequests)
	}
	if joinToken == "" {
		fs.Usage()
		return errors.New("join token required: create the device in the dashboard and run the command it shows")
	}
	if err := refuseGiven(fs, "apply only with --config", "no-inspect", "log-requests"); err != nil {
		return err
	}

	who := currentInvoker(false)
	if who.privileged && !*foreground {
		// The device service runs `run --service`, which keeps the mux.
		if err := refuseGiven(fs, "applies only to a device run in this terminal: add --foreground on Windows, or run without root on Linux and macOS", "no-mux"); err != nil {
			return err
		}
		// The service install or restart may end the terminal session this
		// runs in. The record names no argument, as the join token is one.
		ignoreHangup()
		defer func() { logOutcome([]string{"connect"}, retErr, false) }()
	}
	d, err := prepareDevice(fs, device, who)
	if err != nil {
		return err
	}
	file, err := who.localConfigFile()
	if err != nil {
		return err
	}
	// Read without the lock, only so a config LoadLocal refuses stops
	// connect before the spend. recordDevice re-reads it under the lock.
	if _, err := loadLocalOrEmpty(file); err != nil {
		return err
	}
	// As root on the system layout the store belongs to the agent account:
	// enrolment and the foreground run happen in agent-account children.
	viaChild := needsAgentChild(file)
	if viaChild && *noMux {
		return errors.New("--no-mux is not available to a device enrolled as root; run it as an ordinary user, or leave it out")
	}
	if needsSystemLayout(file) {
		// First: the service check below locks run.lock, which needs the
		// account's group (on Windows its system DACL).
		if err := prepareSystemLayout(context.Background(), file); err != nil {
			return err
		}
	}
	var svc *deviceService
	if who.privileged && !*foreground {
		if svc, err = prepareService(file, ""); err != nil {
			return err
		}
	}
	req := enrolRequest{JoinToken: joinToken, APIURL: resolveAPIURL(*apiURL), Wait: *wait}
	var store *identity.Store
	var res enrolResult
	if viaChild {
		if *foreground {
			// The child run holds run.lock; refuse a holder before the spend.
			release, err := holdRunLock(context.Background(), file, "connect --foreground", false)
			if err != nil {
				return err
			}
			if err := release(); err != nil {
				return err
			}
		}
		if res, err = enrolAsAgent(req); err != nil {
			return err
		}
	} else {
		if store, err = who.store(); err != nil {
			return err
		}
		if who.privileged && *foreground {
			release, err := holdRunLock(context.Background(), file, "connect --foreground", false)
			if err != nil {
				return err
			}
			defer func() { retErr = errors.Join(retErr, release()) }()
		}
		if res, err = enrolInStore(store, req); err != nil {
			return err
		}
	}
	ref := res.Ref

	inForce, err := recordDevice(file, fs, device, who, ref, d)
	if isDeviceNotRecorded(err) {
		return errors.Join(err, forgetUnrecorded(store, viaChild, ref))
	}
	// The device is in the config whenever its entry is in force, even when
	// recordDevice kept the stored settings; the service must then restart
	// to load the new credential.
	if svc != nil && inForce.Identity == ref {
		if installErr := svc.install(); installErr != nil {
			return errors.Join(err, errcode.WithRemedy(
				errcode.New(errcode.EnrolledNotInstalled).With(installErr, fmt.Sprintf("device %s, service %s", ref, svc.manager.Name())),
				"fix the cause, then install the service without a new join token: "+serviceInstallCommand))
		}
	}
	if err != nil {
		return err
	}

	if res.Host != "" {
		fmt.Fprintf(os.Stderr, "  host       %s\n", security.SanitizeDisplay(res.Host))
	}
	fmt.Fprintf(os.Stderr, "  config     %s\n", file.Path)
	printDeviceSettings(inForce)
	if svc != nil {
		fmt.Fprintf(os.Stderr, "  service    %s, running\n\n", svc.manager.Name())
		return nil
	}
	fmt.Fprintln(os.Stderr)
	if viaChild {
		// The child serves every device of the system config, as run does.
		args := []string{"run", "--system"}
		if *noUI {
			args = append(args, "--noui")
		}
		return runAsAgentAccount(args, os.Stdin, os.Stdout)
	}
	return serveEnrolled(context.Background(), version, store, []config.LocalDevice{inForce}, *noUI, *noMux, nil)
}

// storeEnrolledKeys writes the enrolment's key set (session CA keys and
// recording key). The credential is already stored, so a failure warns and
// enrolment goes on: the device accepts no session until ticket_keys.json
// loads, and an identity.KeyRefresher
// fetch (run for every device that serves sessions) or a renewal after the
// file is readable again writes the set. Only
// identity.ErrTicketKeysUnreadable gets the file remedy.
func storeEnrolledKeys(store *identity.Store, ref identity.Ref, set *identity.DeviceKeys) {
	if set == nil {
		return
	}
	keys, err := store.TicketKeys(ref)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  warning: the device's session keys were not saved: %s\n", userText(err))
		return
	}
	// Enrolment runs before the device registers, so no hint is held yet.
	err = keys.Replace(context.Background(), keys.Generation(), *set)
	switch {
	case errors.Is(err, identity.ErrTicketKeysUnreadable):
		fmt.Fprintf(os.Stderr, "  warning: the device's session keys were not saved to %s: %s\n  the device accepts no session until that file loads; fix its mode to owner-only, or remove it if it is malformed, owned by another user or not a regular file, and the next key fetch or renewal writes the set\n", keys.Path(), userText(err))
	case err != nil:
		fmt.Fprintf(os.Stderr, "  warning: the device's session keys were not saved to %s: %s\n", keys.Path(), userText(err))
	}
}

// deviceService is the service a privileged connect installs, checked
// before the join token is spent.
type deviceService struct {
	manager service.Manager
	exe     string
}

// newServiceManager is service.Default, checkServiceBinary is
// security.CheckServiceBinary, enrolDevice and saveIssued are the enrolment
// and credential save of connect, and serveEnrolled is serveDevices; tests
// replace them.
var (
	newServiceManager  = service.Default
	checkServiceBinary = security.CheckServiceBinary
	enrolDevice        = (*identity.Client).EnrolDevice
	saveIssued         = (*identity.Store).SaveIssued
	serveEnrolled      = serveDevices
)

// serviceInstallCommand installs the device service for the enrolled
// devices without a join token.
const serviceInstallCommand = "sudo localport service install (an elevated prompt on Windows)"

// prepareService refuses before the spend what would stop the install after
// it, or what the service must not run: no supported service manager, a
// service definition under the device service's name that localport did not
// write, an executable someone other than root could replace, or a manual
// run holding run.lock, which would keep the started service from serving.
// It lists the systemd drop-ins that extend the service.
func prepareService(file config.LocalConfigFile, exe string) (*deviceService, error) {
	m, err := newServiceManager()
	if err != nil {
		return nil, errcode.WithRemedy(err, "run the device in the foreground with --foreground")
	}
	dropIns, err := m.Check()
	if err != nil {
		return nil, err
	}
	if exe == "" {
		exe, err = serviceExecutable()
	} else {
		err = checkServiceExecutable(exe)
	}
	if err != nil {
		return nil, err
	}
	if err := refuseManualRun(file, m); err != nil {
		return nil, err
	}
	if len(dropIns) > 0 {
		fmt.Fprintf(os.Stderr, "  drop-ins extend %s: %s\n", m.Name(), strings.Join(dropIns, ", "))
	}
	return &deviceService{manager: m, exe: exe}, nil
}

// refuseManualRun refuses while run.lock is held by any process other than
// the running device service carrying the marker, as its manager reports the
// service's main process: a manual run or connect --foreground, or a service
// the manager is starting, stopping or restarting. The installed service
// would otherwise wait on that holder. It only tries run.lock and releases it
// at once; the holder's PID is read only while the try fails.
func refuseManualRun(file config.LocalConfigFile, m service.Manager) error {
	release, err := config.LockRun(file, 0)
	if err == nil {
		return release()
	}
	if !errors.Is(err, config.ErrRunLocked) {
		return err
	}
	holder, holderErr := config.RunLockHolder(file)
	if holderErr != nil {
		return errors.Join(err, holderErr)
	}
	installed, instErr := m.Installed()
	if instErr != nil {
		return errors.Join(err, instErr)
	}
	if installed {
		mainPID, pidErr := m.MainPID(context.Background())
		if pidErr != nil {
			return errors.Join(err, pidErr)
		}
		if holder != 0 && holder == mainPID {
			return nil
		}
	}
	return errcode.WithRemedy(err, fmt.Sprintf("held by process %d, which is not the running device service %s\n  stop a localport run or connect --foreground serving the devices; when the service is starting, stopping or restarting, retry in a few seconds", holder, m.Name()))
}

// serviceRunLockWait bounds how long `run --service` waits for run.lock: a
// restarting service manager can start the new process before the old one
// has released it. A variable so tests can shorten it.
var serviceRunLockWait = 30 * time.Second

// holdRunLock takes run.lock for a privileged run or connect --foreground.
// With asService (run --service) it waits up to serviceRunLockWait, ending
// with ctx, and on giving up returns a service.ExitError with
// service.ExitRunLocked. Any other caller is refused at once while the lock
// is held, naming the device service when one carrying the marker is
// installed. The caller holds the lock until it exits and calls release.
func holdRunLock(ctx context.Context, file config.LocalConfigFile, command string, asService bool) (release func() error, err error) {
	wait := time.Duration(0)
	if asService {
		wait = serviceRunLockWait
	}
	release, err = config.LockRunContext(ctx, file, wait)
	if err == nil || !errors.Is(err, config.ErrRunLocked) {
		return release, err
	}
	if asService {
		return nil, &service.ExitError{Code: service.ExitRunLocked, Err: err}
	}
	m, installed, instErr := installedDeviceService()
	if instErr != nil {
		return nil, errors.Join(err, instErr)
	}
	if installed {
		return nil, errcode.WithRemedy(err, fmt.Sprintf("the device service %s is installed: use it, or stop it before %s", m.Name(), command))
	}
	return nil, errcode.WithRemedy(err, "another localport run or connect --foreground serves them")
}

// unsafeBinaryRemedy follows a security.ErrUnsafeExecutable refusal.
const unsafeBinaryRemedy = `install localport into a directory only root or Administrators can write, then call it by its absolute path: run the install script under sudo (it installs to /usr/local/bin, or /opt/localport/bin when /usr/local/bin is not root-owned) and use sudo /usr/local/bin/localport connect ..., or on Windows run the Localport installer (or install.ps1 elevated, which runs it) and use & "$env:ProgramFiles\Localport\localport.exe" connect ...; a Homebrew, Scoop, winget portable or user-profile install cannot run the device service`

// packageManagerRemedy follows a security.ErrPackageManagerExecutable refusal.
const packageManagerRemedy = `install the device with the Localport installer (localport-setup-<version>-windows-amd64.exe, the winget installer package, or install.ps1 run elevated), then use & "$env:ProgramFiles\Localport\localport.exe" connect ...`

// runningExecutable is service.Executable, a variable so tests name the
// binary a package manager installed.
var runningExecutable = service.Executable

// serviceExecutable is the resolved running binary, refused when a package
// manager installed it or unless only root or Administrators can replace it.
func serviceExecutable() (string, error) {
	exe, err := runningExecutable()
	if err != nil {
		return "", err
	}
	return exe, checkServiceExecutable(exe)
}

// checkServiceExecutable refuses exe as the device service binary when a
// package manager installed it or someone other than root or Administrators
// can replace it.
func checkServiceExecutable(exe string) error {
	if err := security.CheckPackageManagerBinary(exe); err != nil {
		return errcode.WithRemedy(err, packageManagerRemedy)
	}
	if err := checkServiceBinary(exe); err != nil {
		return errcode.WithRemedy(err, unsafeBinaryRemedy)
	}
	return nil
}

// errServiceInstalled refuses deleting the devices while the device
// service that runs them is installed.
var errServiceInstalled = errcode.New(errcode.ServiceInstalled)

// installedDeviceService returns the platform's manager and whether a device
// service carrying the marker is installed. No supported service manager, or
// a definition localport did not write, counts as none.
func installedDeviceService() (service.Manager, bool, error) {
	m, err := newServiceManager()
	if errors.Is(err, service.ErrUnsupported) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	installed, err := m.Installed()
	if errors.Is(err, service.ErrForeignUnit) {
		return m, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return m, installed, nil
}

// install writes, enables and (re)starts the device service, holding the
// service configuration lock. Each service manager command has its own
// timeout.
func (s *deviceService) install() error {
	unlock, err := lockServiceDefinitions(context.Background())
	if err != nil {
		return err
	}
	defer unlock()
	return s.installLocked()
}

// installLocked is install for a caller holding the lock.
func (s *deviceService) installLocked() error {
	return s.manager.Install(context.Background(), s.exe)
}

// mayHaveSpent reports an enrolment failure after which the control plane may
// have redeemed the token: anything but an APIError below 500 (a 4xx refusal
// or a refused redirect), which it answers without redeeming, except the 409
// for a request still in flight under the same key, which may yet redeem it.
func mayHaveSpent(err error) bool {
	var apiErr *identity.APIError
	return !errors.As(err, &apiErr) || apiErr.Status >= 500 || identity.InFlight(err)
}

// errMergeConflict means the flags of a re-enrolment conflict with the
// device's stored settings, which stay in force.
var errMergeConflict = errcode.New(errcode.MergeConflict)

// deviceNotRecorded wraps the failed config write of a newly enrolled
// identity, whose saved credential would then be used by nothing. It adds no
// text, so the user sees the write error as it is.
type deviceNotRecorded struct{ err error }

func (e *deviceNotRecorded) Error() string { return e.err.Error() }

func (e *deviceNotRecorded) Unwrap() error { return e.err }

// isDeviceNotRecorded reports whether err holds a deviceNotRecorded.
func isDeviceNotRecorded(err error) bool {
	var notRecorded *deviceNotRecorded
	return errors.As(err, &notRecorded)
}

// forgetUnrecorded removes the credential of a new identity whose config
// entry was not written, in the agent account's store when viaChild.
func forgetUnrecorded(store *identity.Store, viaChild bool, ref identity.Ref) error {
	var err error
	if viaChild {
		err = runAsAgentAccount([]string{"identity", "remove", ref.String()}, nil, io.Discard)
	} else if err = store.Remove(context.Background(), ref); err == nil {
		fmt.Fprintf(os.Stderr, "  removed %s, which no config entry uses\n", ref)
	}
	if err != nil {
		return errcode.WithRemedy(err, fmt.Sprintf("the credential of %s was not removed; remove it with: localport identity remove %s", ref, ref))
	}
	return nil
}

// recordDevice records an enrolled device in the local config, under its
// lock. A stored entry with the same identity takes the flags given as set
// does (each given flag overrides, the rest keep their stored values); a new
// identity appends fresh, the entry the flags alone describe. When the merge
// is invalid the config is left unchanged and the error wraps
// errMergeConflict. It returns the entry in force.
func recordDevice(file config.LocalConfigFile, fs *flag.FlagSet, flags *deviceFlags, who invoker, ref identity.Ref, fresh config.LocalDevice) (config.LocalDevice, error) {
	unlock, err := config.LockLocal(file)
	if err != nil {
		return config.LocalDevice{}, errcode.WithRemedy(err, joinTokenSpent)
	}
	defer unlock()
	local, err := loadLocalOrEmpty(file)
	if err != nil {
		return config.LocalDevice{}, errcode.WithRemedy(err, joinTokenSpent)
	}

	i := slices.IndexFunc(local.Devices, func(d config.LocalDevice) bool { return d.Identity == ref })
	if i < 0 {
		fresh.Identity = ref
		local.Devices = append(local.Devices, fresh)
		if err := writeLocal(file, local, ref); err != nil {
			return config.LocalDevice{}, errcode.WithRemedy(errcode.New(errcode.EnrolledNotRecorded).With(&deviceNotRecorded{err}, "device "+ref.String()), joinTokenSpent)
		}
		return fresh, nil
	}

	stored := local.Devices[i]
	merged := stored
	if err := flags.apply(fs, &merged, who); err != nil {
		return stored, mergeConflict(ref, err)
	}
	if merged.Equal(stored) {
		return stored, nil
	}
	local.Devices[i] = merged
	switch err := writeLocal(file, local, ref); {
	case err == nil:
		return merged, nil
	case errors.Is(err, config.ErrInvalidLocalConfig):
		return stored, mergeConflict(ref, err)
	case errors.Is(err, config.ErrFilesRootMissing):
		return stored, errcode.WithRemedy(err, fmt.Sprintf("device %s keeps its new credential and its stored settings\n  mount or create its files root, or change it with: localport set %s --files-root DIR",
			ref, ref.Identity))
	default:
		return stored, errcode.WithRemedy(errcode.New(errcode.EnrolledNotRecorded).With(err, "device "+ref.String()), joinTokenSpent)
	}
}

// writeLocal is config.WriteLocal; tests replace it to force a write failure.
var writeLocal = config.WriteLocal

func mergeConflict(ref identity.Ref, err error) error {
	return errMergeConflict.With(err, fmt.Sprintf("device %s keeps its new credential and its stored settings\n  change them with: localport set %s [flags]",
		ref, ref.Identity))

}

// printDeviceSettings prints what a device allows.
func printDeviceSettings(d config.LocalDevice) {
	or := func(s, none string) string {
		if s == "" {
			return none
		}
		return s
	}
	enable := make([]string, len(d.Enable))
	for i, c := range d.Enable {
		enable[i] = string(c)
	}
	fmt.Fprintf(os.Stderr, "  enable     %s\n", or(strings.Join(enable, ","), "ports only"))
	fmt.Fprintf(os.Stderr, "  logins     %s\n", or(strings.Join(d.Logins, ","), "none"))
	if len(d.PasswordLogins) > 0 {
		fmt.Fprintf(os.Stderr, "  password   %s (asked at each session)\n", strings.Join(d.PasswordLogins, ","))
	}
	fmt.Fprintf(os.Stderr, "  target     %s\n", or(d.Host, "this machine"))
	fmt.Fprintf(os.Stderr, "  ports      %s\n", or(d.AllowPorts.String(), "any the dashboard allows"))
	if d.FilesRoot != "" {
		fmt.Fprintf(os.Stderr, "  files root %s\n", d.FilesRoot)
	}
	if d.RDP != "" {
		fmt.Fprintf(os.Stderr, "  rdp        %s\n", d.RDP)
	}
	if d.VNC != "" {
		fmt.Fprintf(os.Stderr, "  vnc        %s\n", d.VNC)
	}
}

// joinTokenSpent is the remedy printed when enrolment succeeded but its
// result could not be kept.
const joinTokenSpent = "the join token is spent: create a new join token for this device in the dashboard and run connect again"

// errExtraArgument refuses an argument beyond the one join token.
var errExtraArgument = errcode.New(errcode.ExtraArgument)

// prepareDevice builds and validates the device's local settings from the
// flags alone before any join token is spent: the identity, and so any stored
// entry, is unknown until enrolment. A refusal a stored entry might have
// satisfied names the re-enrol-then-set remedy.
func prepareDevice(fs *flag.FlagSet, flags *deviceFlags, who invoker) (config.LocalDevice, error) {
	var d config.LocalDevice
	err := flags.apply(fs, &d, who)
	if err == nil {
		err = d.ValidateSettings()
	}
	if errors.Is(err, config.ErrLoginsWithoutSession) || errors.Is(err, config.ErrDesktopWithoutTarget) || errors.Is(err, errNoDefaultLogin) {
		return d, errcode.WithRemedy(err, "before enrolment these flags are checked without the device's stored settings: re-enrol without them, then change them with localport set")
	}
	if err != nil {
		return d, err
	}
	if d.FilesRoot != "" {
		if err := config.CheckFilesRoot(d.FilesRoot); err != nil {
			return d, fmt.Errorf("--files-root: %w", err)
		}
	}
	return d, nil
}

// runConfigFile runs every tunnel in a config file.
func runConfigFile(version, path string, noUI, noMux, noInspect, logRequests bool) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	cfg.NoMux = noMux
	cfg.AgentVersion = version
	mode := ui.DetectMode(noUI, os.Stderr)
	cfg.NoInspect = inspectDisabled(mode, noInspect, logRequests)

	a := agent.New(cfg)
	renderer := pickRenderer(mode, a)
	renderer.Banner(version, cfg)
	defer renderer.Shutdown()

	// Stop ends all sessions at once. The renderer shuts down first to
	// restore the terminal before teardown output.
	ctx, stop := signalContext(func() {
		renderer.Shutdown()
		a.Stop()
	})
	defer stop()

	// An edge refusal prints as its message and code (errcode.Render).
	runErr := a.Run(ctx, renderer)
	renderer.Shutdown()
	return runErr
}

func usageConnect(fs *flag.FlagSet) {
	fmt.Fprint(os.Stderr, `Usage: localport connect <join-token> [--enable terminal,files,desktop] [--logins a,b]
                         [--files-root DIR] [--rdp[=HOST:PORT]] [--vnc[=HOST:PORT]]
                         [--host HOST] [--allow-ports LIST] [--foreground]
       localport connect --config localport.yaml

  Enrol this machine as a fleet device. Create the device in the dashboard;
  it shows the command with a single-use join token. The machine keeps a
  private key that never leaves it. The device's settings go to the local
  config, which only its owner can change (localport set). A second connect
  with a new token for an enrolled device replaces its credential.

  As root (Administrator on Windows), the device is recorded in the
  machine-wide config, and connect installs and starts the device service
  (systemd localport-device.service, launchd io.localport.device, Windows
  service localport-device), which runs every enrolled device at boot.
  connect is refused while a manual localport run serves the devices.

  The service runs this binary, so only root (Administrators) may be able to
  replace it. Install it with the install script under sudo or an elevated
  install.ps1, and call it by that absolute path. A Homebrew, Scoop, winget
  or user-profile install cannot run the device service.

  --foreground runs the device in this terminal instead, and is refused while
  another process (the device service or a manual run) serves the devices.
  As root on Linux and macOS it runs every device in the machine-wide config,
  as localport run --system does, under the localport account; --no-mux is
  not available there.

  Without root, the device is recorded in $LOCALPORT_HOME/agent.yaml and runs
  in the foreground, and --logins may name only the user running the command.

  --logins defaults to $SUDO_USER when set and not root, otherwise the user
  running the command; root only when listed. terminal and files act on this
  machine and are refused with --host and on Windows. desktop needs --rdp or
  --vnc.

  Every tunnel in a file. The file sets them all, so device flags are refused
  beside it:
    localport connect --config localport.yaml


Flags:
`)
	fs.PrintDefaults()
}

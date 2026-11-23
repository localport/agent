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

// joinTokenPrefix starts every join token the dashboard issues; it tells
// `up <join-token>` from `up <device>`.
const joinTokenPrefix = "lpj_"

// runUp enrols this machine as a fleet device with a single-use join token
// and records it in the local config. As root or an elevated Administrator it
// then installs and starts the device service, unless --foreground;
// otherwise it runs the device in the foreground. With --config it runs every
// tunnel in a config file. A run that installs the service runs to the end
// through a hangup of its terminal and records its outcome in the system log.
// Without a join token or --config it resumes paused devices (runPause).
func runUp(version string, args []string) (retErr error) {
	if resumesDevices(args) {
		return runPause("up", args, false)
	}
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		configPath  = fs.String("config", "", "path to a YAML config of tunnels")
		apiURL      = fs.String("api", "", "control plane base URL (default "+identity.DefaultAPIURL+")")
		wait        = fs.Duration("wait", identity.DefaultRetryBudget, "how long to keep retrying while the control plane is unreachable (0 = one attempt)")
		noUI        = fs.Bool("noui", false, "disable the live view and emit plain logs (auto-enabled when stderr is not a TTY)")
		noMux       = fs.Bool("no-mux", false, "send each inbound connection over its own connection instead of multiplexing them; a device then serves no browser or CLI sessions; as Administrator on Windows only with --foreground or --config, as root on Linux and macOS only with --config")
		noInspect   = fs.Bool("no-inspect", false, "do not inspect HTTP requests (--config)")
		logRequests = fs.Bool("log-requests", false, "log one line per HTTP request in headless mode (--config)")
		foreground  = fs.Bool("foreground", false, "run the devices in this terminal instead of installing the service (root or Administrator): every device in the machine-wide config")
	)
	device := addDeviceFlags(fs)
	fs.Usage = func() { usageUp(fs) }

	// The join token is a leading positional, as the dashboard shows it.
	joinToken, rest := "", args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		joinToken, rest = args[0], args[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return errcode.UsageError(err)
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
			return errcode.New(errcode.JoinTokenWithConfig)
		}
		if err := refuseBesideConfig(fs, *configPath, "enable", "logins", "files-root", "host", "allow-ports", "rdp", "vnc", "api", "wait", "foreground"); err != nil {
			return err
		}
		return runConfigFile(version, *configPath, *noUI, *noMux, *noInspect, *logRequests)
	}
	if joinToken == "" {
		fs.Usage()
		return errcode.New(errcode.JoinTokenRequired)
	}
	// A device name beside an enrolment flag lands here; it is no token, so it
	// must not reach the control plane.
	if !strings.HasPrefix(joinToken, joinTokenPrefix) {
		return errcode.WithRemedy(errNotJoinToken.With(nil, fmt.Sprintf("%q", security.SanitizeDisplay(joinToken))),
			"enrolment flags apply only with a join token; resume a device "+elevatedCommand("up <device>"))
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
		defer func() { logOutcome([]string{"up"}, retErr, false) }()
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
	// up before the spend. recordDevice re-reads it under the lock.
	if _, err := loadLocalOrEmpty(file); err != nil {
		return err
	}
	// As root on the system layout the store belongs to the agent account:
	// enrolment and the foreground run happen in agent-account children.
	viaChild := needsAgentChild(file)
	if viaChild && *noMux {
		return errcode.New(errcode.NoMuxAsRoot)
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
	// A privileged up --foreground holds run.lock from before the token spend
	// and opens its control endpoint right after, so up, down and set reach
	// the run while it enrols. heldRun and heldControl are the lock and the
	// socket the child run serves the devices under (runHeldAsAgent);
	// heldReloads are the requests this process serves the devices with.
	var heldRun *os.File
	var heldControl *startingControl
	var heldReloads reloadSource
	if viaChild {
		if *foreground {
			lock, release, err := holdRunLock(context.Background(), file, "up --foreground", false)
			if err != nil {
				return err
			}
			defer func() { retErr = errors.Join(retErr, release()) }()
			heldRun = lock
			if heldControl, err = openStartingControl(); err != nil {
				return err
			}
			defer func() { retErr = errors.Join(retErr, heldControl.Close()) }()
		}
	} else {
		if store, err = who.store(); err != nil {
			return err
		}
		if who.privileged && *foreground {
			_, release, err := holdRunLock(context.Background(), file, "up --foreground", false)
			if err != nil {
				return err
			}
			defer func() { retErr = errors.Join(retErr, release()) }()
			var stop func()
			if heldReloads, stop, err = openRunControl(); err != nil {
				return err
			}
			defer stop()
		}
	}
	// The config lock, taken after run.lock as every holder of both does,
	// covers the enrolment through recordDevice: a concurrent up or down reads
	// the store facts under it, so none prunes this entry on a tombstone the
	// enrolment is about to replace.
	unlockConfig, err := config.LockLocal(file)
	if err != nil {
		return err
	}
	facts, err := refuseFullConfig(file, who)
	if err != nil {
		unlockConfig()
		return err
	}
	if viaChild {
		res, err = enrolAsAgent(req)
	} else {
		res, err = enrolInStore(store, req)
	}
	if err != nil {
		unlockConfig()
		return err
	}
	ref := res.Ref

	inForce, err := recordDevice(file, fs, device, who, ref, d, facts)
	unlockConfig()
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
		return runHeldAsAgent(args, os.Stdin, os.Stdout, heldRun, heldControl)
	}
	if who.privileged {
		// This process holds run.lock and serves the control endpoint (above)
		// and serves every device of the system config, as the relayed run does.
		return serveHeld(context.Background(), version, who, file, *noUI, *noMux, heldReloads)
	}
	return serveEnrolled(context.Background(), version, store, []config.LocalDevice{inForce}, *noUI, *noMux, nil)
}

// storeEnrolledKeys writes the enrolment's key set (session CA keys and
// recording key). The credential is already stored, so a failure warns and
// enrolment goes on: the device accepts no session until ticket_keys.json
// loads, and an identity.KeyRefresher fetch (run for every device that serves
// sessions) or a renewal after the file is readable again writes the set. Only
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

// deviceService is the service a privileged up installs, checked
// before the join token is spent.
type deviceService struct {
	manager service.Manager
	exe     string
}

// newServiceManager is service.Default, checkServiceBinary is
// security.CheckServiceBinary, enrolDevice and saveIssued are the enrolment
// and credential save of up, serveEnrolled is serveDevices and serveHeld is
// serveHeldDevices; tests replace them.
var (
	newServiceManager  = service.Default
	checkServiceBinary = security.CheckServiceBinary
	enrolDevice        = (*identity.Client).EnrolDevice
	saveIssued         = (*identity.Store).SaveIssued
	serveEnrolled      = serveDevices
	serveHeld          = serveHeldDevices
)

// serviceInstallCommand installs the device service for the enrolled
// devices without a join token.
var serviceInstallCommand = elevatedLocalport() + " service install" + elevatedNote()

// prepareService refuses, before the spend, what would stop the install after
// it or what the service must not run: no supported service manager, a foreign
// service definition under its name, an executable someone other than root
// could replace, on macOS a missing or unsigned Localport.app beside it, or a
// manual run holding run.lock, which would block the service. It also lists
// the service's systemd drop-ins.
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
	if c, ok := m.(service.AppChecker); ok {
		if err := c.CheckApp(context.Background(), exe); err != nil {
			return nil, err
		}
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
// service's main process: a manual run or up --foreground, or a service
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
	return errcode.WithRemedy(err, fmt.Sprintf("held by process %d, which is not the running device service %s\n  stop a localport run or up --foreground serving the devices; when the service is starting, stopping or restarting, retry in a few seconds", holder, m.Name()))
}

// serviceRunLockWait is how long `run --service` waits for run.lock before it
// reads the holder as a foreground run: a restarting service manager can
// start the new process before the old one has released it. A variable so
// tests can shorten it.
var serviceRunLockWait = 30 * time.Second

// standbyRetry is each run.lock wait of a standing-by service; the wait
// repeats until the lock is free or the service stops.
const standbyRetry = time.Hour

// runLockedRemedy follows a refusal because another process serves the devices.
const runLockedRemedy = "another localport run or up --foreground serves them"

// holdRunLock takes run.lock for a privileged run or up --foreground. With
// asService (run --service) it stands by for the lock (holdServiceRunLock);
// any other caller is refused while the lock is held, naming the device
// service when ours is installed. The caller holds the lock until it exits
// and calls release. lock is the locked file, passed by some callers to the
// agent-account child serving the devices (runHeldAsAgent).
func holdRunLock(ctx context.Context, file config.LocalConfigFile, command string, asService bool) (lock *os.File, release func() error, err error) {
	if asService {
		return holdServiceRunLock(ctx, file)
	}
	lock, release, err = config.LockRunFile(ctx, file, 0)
	if err == nil || !errors.Is(err, config.ErrRunLocked) {
		return lock, release, err
	}
	m, installed, instErr := installedDeviceService()
	if instErr != nil {
		return nil, nil, errors.Join(err, instErr)
	}
	if installed {
		byService, checkErr := serviceHoldsRunLock(file, m)
		if checkErr != nil {
			return nil, nil, errors.Join(err, checkErr)
		}
		if byService {
			return nil, nil, errcode.WithRemedy(err, fmt.Sprintf("the device service %s is installed: use it, or stop it with %s, then run %s again", m.Name(), elevatedStop(m), command))
		}
	}
	return nil, nil, errcode.WithRemedy(err, runLockedRemedy)
}

// serviceHoldsRunLock reports whether the running device service is the
// recorded run.lock holder, not one standing by beside a foreground run.
func serviceHoldsRunLock(file config.LocalConfigFile, m service.Manager) (bool, error) {
	holder, err := config.RunLockHolder(file)
	if err != nil || holder == 0 {
		return false, err
	}
	mainPID, err := m.MainPID(context.Background())
	return err == nil && mainPID == holder, err
}

// holdServiceRunLock takes run.lock for `run --service`. It waits up to
// serviceRunLockWait for a restart's previous process to exit; a lock still
// held then belongs to a foreground run (run, up --foreground). The service
// then logs once and waits for the lock with no deadline, taking the devices
// over when that run ends, never restarted in a loop by its manager. The wait
// ends with ctx (Stop on Windows; the stop signal ends it on Linux and macOS).
func holdServiceRunLock(ctx context.Context, file config.LocalConfigFile) (lock *os.File, release func() error, err error) {
	lock, release, err = config.LockRunFile(ctx, file, serviceRunLockWait)
	if !errors.Is(err, config.ErrRunLocked) {
		return lock, release, err
	}
	holder := "another process"
	if pid, pidErr := config.RunLockHolder(file); pidErr == nil && pid != 0 {
		holder = fmt.Sprintf("process %d", pid)
	}
	logEventf("a foreground run (%s) holds %s and serves the devices; the device service waits and takes them over when it ends", holder, file.RunLockPath())
	for errors.Is(err, config.ErrRunLocked) {
		lock, release, err = config.LockRunFile(ctx, file, standbyRetry)
	}
	return lock, release, err
}

// unsafeBinaryRemedy follows a security.ErrUnsafeExecutable refusal.
const unsafeBinaryRemedy = `install localport into a directory only root or Administrators can write, then call it by its absolute path: run the install script under sudo (it installs to /usr/local/bin, or /opt/localport/bin when /usr/local/bin is not root-owned) and use sudo /usr/local/bin/localport up ..., or on Windows run the Localport installer (or install.ps1 elevated, which runs it) and use & "$env:ProgramFiles\Localport\localport.exe" up ...; a Homebrew, Scoop, winget portable or user-profile install cannot run the device service`

// packageManagerRemedy follows a security.ErrPackageManagerExecutable refusal.
const packageManagerRemedy = `install the device with the Localport installer (localport-setup-<version>-windows-amd64.exe, the winget installer package, or install.ps1 run elevated), then use & "$env:ProgramFiles\Localport\localport.exe" up ...`

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

// install writes, enables and (re)starts the device service under the
// service configuration lock; each service manager command has its own timeout.
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

// refuseFullConfig refuses an enrolment before the token is spent when the
// config already lists config.MaxDevices devices that recordDevice would not
// prune. It returns the store facts it read for a full config, which hold
// under the config's lock the caller keeps until recordDevice; nil otherwise.
func refuseFullConfig(file config.LocalConfigFile, who invoker) (map[identity.Ref]deviceFact, error) {
	local, err := loadLocalOrEmpty(file)
	if err != nil || len(local.Devices) < config.MaxDevices {
		return nil, err
	}
	facts, err := readFacts(file, who, local.Devices)
	if err != nil {
		return nil, err
	}
	if len(local.Devices)-len(pruneRemoved(local, facts)) < config.MaxDevices {
		return facts, nil
	}
	return nil, errcode.WithRemedy(errcode.New(errcode.DeviceLimit).With(nil, fmt.Sprintf("%d devices", config.MaxDevices)),
		"remove a device from this machine in the dashboard, then run up again; enrolling a device this machine already serves again also needs a free place")
}

// recordDevice records an enrolled device in the local config. The caller
// holds the config's lock (config.LockLocal). A stored entry with the same
// identity takes the flags given as set does (each given flag overrides, the
// rest keep their stored values); a new identity appends fresh, the entry the
// flags alone describe. When the merge is invalid the config is left
// unchanged and the error wraps errMergeConflict. facts, when not nil, are
// the store facts read under the same lock hold before the enrolment;
// otherwise they are read here. It returns the entry in force.
func recordDevice(file config.LocalConfigFile, fs *flag.FlagSet, flags *deviceFlags, who invoker, ref identity.Ref, fresh config.LocalDevice, facts map[identity.Ref]deviceFact) (config.LocalDevice, error) {
	local, err := loadLocalOrEmpty(file)
	if err != nil {
		return config.LocalDevice{}, errcode.WithRemedy(err, joinTokenSpent)
	}
	// Entries of forgotten devices go with this write. The credential is kept
	// whatever happens here, so a failed read only skips the pruning.
	var pruned []deviceFact
	if facts == nil {
		var factsErr error
		if facts, factsErr = readFacts(file, who, local.Devices); factsErr != nil {
			fmt.Fprintf(os.Stderr, "  warning: removed devices were not pruned from the config: %s\n", userText(factsErr))
		}
	}
	if facts != nil {
		// The enrolment replaced ref's credential and tombstone.
		delete(facts, ref)
		pruned = pruneRemoved(local, facts)
	}
	// keepPruned writes the pruning alone when the entry itself is not
	// written; a failure only warns, as the read above does.
	keepPruned := func() {
		if err := writePruned(file, local, pruned); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: removed devices were not pruned from the config: %s\n", userText(err))
		}
	}

	i := slices.IndexFunc(local.Devices, func(d config.LocalDevice) bool { return d.Identity == ref })
	if i < 0 {
		fresh.Identity = ref
		local.Devices = append(local.Devices, fresh)
		if err := writeLocal(file, local, ref); err != nil {
			return config.LocalDevice{}, errcode.WithRemedy(errcode.New(errcode.EnrolledNotRecorded).With(&deviceNotRecorded{err}, "device "+ref.String()), joinTokenSpent)
		}
		reportPruned(pruned)
		return fresh, nil
	}

	stored := local.Devices[i]
	merged := stored
	if err := flags.apply(fs, &merged, who); err != nil {
		keepPruned()
		return stored, mergeConflict(ref, stored, err)
	}
	merged.Paused = false
	if merged.Equal(stored) {
		keepPruned()
		return stored, nil
	}
	local.Devices[i] = merged
	switch err := writeLocal(file, local, ref); {
	case err == nil:
		reportPruned(pruned)
		return merged, nil
	case errors.Is(err, config.ErrInvalidLocalConfig):
		return stored, mergeConflict(ref, stored, err)
	case errors.Is(err, config.ErrFilesRootMissing):
		return stored, errcode.WithRemedy(err, fmt.Sprintf("%s\n  mount or create its files root, or change it with: localport set %s --files-root DIR",
			keptSettings(ref, stored), ref.Identity))
	default:
		return stored, errcode.WithRemedy(errcode.New(errcode.EnrolledNotRecorded).With(err, "device "+ref.String()), joinTokenSpent)
	}
}

// writeLocal is config.WriteLocal; tests replace it to force a write failure.
var writeLocal = config.WriteLocal

func mergeConflict(ref identity.Ref, stored config.LocalDevice, err error) error {
	return errMergeConflict.With(err, fmt.Sprintf("%s\n  change them with: localport set %s [flags]",
		keptSettings(ref, stored), ref.Identity))
}

// keptSettings says that a re-enrolled device whose settings could not be
// merged keeps its stored ones, a pause included.
func keptSettings(ref identity.Ref, stored config.LocalDevice) string {
	kept := fmt.Sprintf("device %s keeps its new credential and its stored settings", ref)
	if stored.Paused {
		kept += fmt.Sprintf(", and stays paused until: %s up %s", elevatedLocalport(), ref.Identity)
	}
	return kept

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
const joinTokenSpent = "the join token is spent: create a new join token for this device in the dashboard and run up again"

// errExtraArgument refuses an argument the command does not take.
var errExtraArgument = errcode.New(errcode.ExtraArgument)

// errNotJoinToken refuses a first argument that is not a join token.
var errNotJoinToken = errcode.New(errcode.NotJoinToken)

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
			return d, errcode.InvalidArgf("--files-root: %w", err)
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

// resumesDevices reports whether up's arguments resume enrolled devices
// (`up [<device> | --all]`) rather than enrol with a join token or run a
// config file: no join token and no flag other than --all.
func resumesDevices(args []string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, joinTokenPrefix) {
			return false
		}
		if name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "="); strings.HasPrefix(a, "-") && name != "all" {
			return false
		}
	}
	return true
}

func usageUp(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, `Usage: localport up <join-token> [--enable terminal,files,desktop] [--logins a,b]
                    [--files-root DIR] [--rdp[=HOST:PORT]] [--vnc[=HOST:PORT]]
                    [--host HOST] [--allow-ports LIST] [--foreground]
       localport up --config localport.yaml
       %[1]s up [<device> | --all]%[2]s

  Enrol this machine as a fleet device. Create the device in the dashboard;
  it shows the command with a single-use join token. The machine keeps a
  private key that never leaves it. The device's settings go to the local
  config, which only its owner can change (localport set). A second up with
  a new token for an enrolled device replaces its credential and resumes it
  when paused.

  As root (Administrator on Windows), the device is recorded in the
  machine-wide config, and up installs and starts the device service
  (systemd localport-device.service, launchd io.localport.device, Windows
  service localport-device), which runs every enrolled device at boot.
  up is refused while a manual localport run serves the devices.

  Without a join token, up resumes a device paused with localport down and
  retries one the agent stopped after a refusal, then reloads the device
  service, or starts it when it is installed and stopped.

  The service runs this binary, so only root (Administrators) may be able to
  replace it. Install it with the install script under sudo or an elevated
  install.ps1, and call it by that absolute path. A Homebrew, Scoop, winget
  or user-profile install cannot run the device service.

  --foreground runs the device in this terminal instead, and is refused while
  another process (the device service or a manual run) serves the devices.
  As root on Linux and macOS it runs every device in the machine-wide config,
  as localport run --system does, under the agent account; --no-mux is
  not available there. On Windows it also runs every device in the
  machine-wide config. up, down and set reach that run through its control
  endpoint.

  Without root, the device is recorded in $LOCALPORT_HOME/agent.yaml and runs
  in the foreground, and --logins may name only the user running the command.

  --logins defaults to $SUDO_USER when set and not root, otherwise the user
  running the command; root only when listed. terminal and files act on this
  machine and are refused with --host and on Windows. desktop needs --rdp or
  --vnc.

  Every tunnel in a file. The file sets them all, so device flags are refused
  beside it:
    localport up --config localport.yaml


Flags:
`, elevatedLocalport(), elevatedNote())
	fs.PrintDefaults()
}

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/localport/agent/internal/agent"
	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/recording"
	"github.com/localport/agent/internal/service"
	"github.com/localport/agent/internal/session"
	"github.com/localport/agent/internal/status"
	"github.com/localport/agent/internal/tunnel"
	"github.com/localport/agent/internal/ui"
)

type runFlags struct {
	noUI, system, asService *bool
	logFile                 *string
}

// newRunFlags is run's flag set, shared by runRun and by root's check that a
// relayed run will serve devices (runRunAsAgent).
func newRunFlags() (*flag.FlagSet, runFlags) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	return fs, runFlags{
		noUI:      fs.Bool("noui", false, "disable the live view and emit plain logs (auto-enabled when stderr is not a TTY)"),
		system:    fs.Bool("system", false, "serve the machine-wide config and credentials (root or an elevated Administrator)"),
		asService: fs.Bool("service", false, "run as the installed device service (implies --system)"),
		logFile:   fs.String("log-file", "", "write stdout and stderr to this file and rotate it (launchd, OpenRC)"),
	}
}

// runServesInForeground reports whether `run` with args gets past its flags
// to serve devices in the foreground: a help request or a flag error ends it
// first, and --service runs as the device service.
func runServesInForeground(args []string) bool {
	fs, f := newRunFlags()
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return fs.Parse(args) == nil && fs.NArg() == 0 && !*f.asService
}

// runRun runs every device enrolled in the local config. Every generated
// service definition runs it with --service. Started by the Windows service
// control manager, it runs under the manager's control loop and stops when
// the manager stops the service.
func runRun(version string, args []string) error {
	fs, f := newRunFlags()
	fs.SetOutput(os.Stderr)
	fs.Usage = usageRun
	if err := fs.Parse(args); err != nil {
		return err
	}
	noUI, system, asService, logFile := f.noUI, f.system, f.asService, f.logFile
	if fs.NArg() > 0 {
		usageRun()
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	// A foreground run of the system devices must be one up, down and set can
	// reach, which only root's (an elevated Administrator's) is.
	if *system && !*asService && !asAgentChild && !privilegedProcess() {
		return errcode.New(errcode.SystemRunNotPrivileged)
	}
	if *logFile != "" {
		// Rotation runs for the life of the process.
		if err := startLogFile(context.Background(), *logFile); err != nil {
			return err
		}
	}

	who := currentInvoker(*system || *asService)
	// Under the Windows service control manager everything, config loading
	// included, runs inside the manager's control loop.
	if underSCM, err := service.RunUnderSCM(version, func(ctx context.Context, running func()) error {
		return runEnrolledDevices(ctx, version, who, *asService, true, running)
	}); underSCM || err != nil {
		return err
	}
	return runEnrolledDevices(context.Background(), version, who, *asService, *noUI, func() {})
}

// runEnrolledDevices loads the local config and serves its devices. A
// privileged process first re-checks that only root or Administrators can
// replace its binary, then holds run.lock until it returns (see
// holdRunLock) and serves the devices with serveHeldDevices; the config is
// loaded only once the lock is held. running is called after the binary
// check, before the run.lock wait.
func runEnrolledDevices(ctx context.Context, version string, who invoker, asService, noUI bool, running func()) (retErr error) {
	file, err := who.localConfigFile()
	if err != nil {
		return err
	}
	if who.privileged {
		if _, err := serviceExecutable(); err != nil {
			return err
		}
	}
	// Before the run.lock wait: under the Windows service control manager the
	// service then accepts Stop, which ends the wait through ctx.
	running()
	if !who.privileged {
		cfg, err := config.LoadLocal(file)
		if err != nil {
			return err
		}
		store, err := who.store()
		if err != nil {
			return err
		}
		return serveDevicesOn(ctx, version, store, cfg.Devices, noUI, false, nil, nil, nil)
	}
	var release func() error
	if asAgentChild && !asService {
		// Root holds run.lock for this run and passed it (runHeldAsAgent).
		release, err = inheritedRunLock(file)
	} else {
		_, release, err = holdRunLock(ctx, file, "localport run", asService)
	}
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, release()) }()
	var reloads reloadSource
	if !asService {
		var stop func()
		if reloads, stop, err = openRunControl(); err != nil {
			return err
		}
		defer stop()
	}
	return serveHeldDevices(ctx, version, who, file, noUI, false, reloads)
}

// openRunControl serves the control endpoint of a foreground run that holds
// run.lock (serveControl), right after it takes the lock: a run root relays as
// the agent account accepts on the socket root passed (runHeldAsAgent, socket
// activation), any other opens the endpoint itself. stop closes it; the caller
// calls stop before releasing run.lock. A variable so tests can replace it.
var openRunControl = func() (reloads reloadSource, stop func(), err error) {
	var ctl *launcher.ControlListener
	if asAgentChild {
		ctl, err = inheritedControl()
	} else {
		ctl, err = listenControl()
	}
	if err != nil {
		return nil, nil, controlEndpointFailed(err)
	}
	reloads, stop = serveControl(ctl)
	return reloads, stop, nil
}

// serveHeldDevices serves every device of file, the system config, for the
// process holding its run.lock: it publishes the devices' states to the
// session launcher and reloads the config on each reload request. A
// foreground run passes reloads, the requests from its control endpoint
// (openRunControl); the service passes nil and takes them from its manager
// (SIGHUP on Unix, a parameter change on Windows). It subscribes to the
// requests before it reads the config, so a request from then on is queued
// for the devices' runner, never lost: a foreground run answers `starting`
// only before this point (controlReloads), and on Unix the service's SIGHUP
// never takes its default exit.
func serveHeldDevices(ctx context.Context, version string, who invoker, file config.LocalConfigFile, noUI, noMux bool, reloads reloadSource) error {
	// The connection closes before run.lock is released.
	board := status.NewBoard(os.Getpid())
	stopPublishing := startPublishing(ctx, board)
	defer stopPublishing()
	if reloads == nil {
		reloads = notifyReload
	}
	sig, stopReloads := reloads()
	defer stopReloads()
	subscribed := func() (<-chan os.Signal, func()) { return sig, func() {} }
	cfg, err := config.LoadLocal(file)
	if err != nil {
		return err
	}
	store, err := who.store()
	if err != nil {
		return err
	}
	load := func() ([]config.LocalDevice, error) {
		cfg, err := config.LoadLocal(file)
		if err != nil {
			return nil, err
		}
		return cfg.Devices, nil
	}
	return serveDevicesOn(ctx, version, store, cfg.Devices, noUI, noMux, load, subscribed, board)
}

// listenControl is launcher.ListenControl; tests replace it.
var listenControl = launcher.ListenControl

// openStatus opens the launcher's status publication; tests replace it.
var openStatus status.Opener = launcher.DefaultClient().OpenStatus

// startPublishing runs status.Publish for board and returns a function that
// stops it and waits until its connection is closed.
func startPublishing(ctx context.Context, board *status.Board) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		status.Publish(ctx, board, openStatus, logEventf)
	}()
	return func() {
		cancel()
		<-done
	}
}

// serveDevices is serveDevicesOn without a status board.
func serveDevices(parent context.Context, version string, store *identity.Store, devices []config.LocalDevice, noUI, noMux bool, reload func() ([]config.LocalDevice, error)) error {
	return serveDevicesOn(parent, version, store, devices, noUI, noMux, reload, nil, nil)
}

// serveDevicesOn runs the enrolled devices until a signal or parent ends,
// with the renewal loop of each renewable credential. A device whose
// credential is missing or unreadable is logged and skipped. Without reload
// the run refuses to start when no device can, and returns when the last one
// ends; with it (the run.lock holder, serveHeldDevices) it keeps going with
// none until stopped, and each request from reloads (notifyReload when nil)
// re-reads the devices and applies the changed ones (deviceRunner.reload). A
// device refused for good is forgotten (SE018, SE041) or parked
// (deviceRunner.handleEnd). noMux serves every inbound connection on its own
// connection, so no sessions run. board, when set, receives each device's
// state for the status endpoint.
func serveDevicesOn(parent context.Context, version string, store *identity.Store, devices []config.LocalDevice, noUI, noMux bool, reload func() ([]config.LocalDevice, error), reloads reloadSource, board *status.Board) error {
	// Each line names its own topic (identity, session, reload).
	logEvent := func(line string) { fmt.Fprintf(os.Stderr, "  [event] %s\n", line) }
	cfg := &config.Config{AgentVersion: version, NoMux: noMux}
	var a *agent.Agent
	runner := &deviceRunner{parent: parent, store: store, logEvent: logEvent, served: map[identity.Ref]*servedDevice{},
		forget: store.Forget, endWake: make(chan struct{}, 1), board: board, reloads: reloads, fda: tunnel.NewFullDiskAccessState()}
	runner.configured.Store(&devices)
	// The uploader runs only after a is set.
	runner.uploads = openUploader(store, runner.isConfigured, func(identifier string) (recording.Client, error) {
		return deviceRecordingClient(a, identifier)
	})
	uploads := runner.uploads
	runner.notices = tunnel.NewClipboardNotices(func(identifier string) (*tunnel.ClipboardClient, error) {
		return deviceClipboardClient(a, identifier)
	})
	// With noMux no session runs, so the launcher is not probed.
	runner.probed, runner.noMux = noMux, noMux
	defer func() {
		for _, s := range runner.served {
			s.end()
		}
	}()
	for _, d := range devices {
		if spec, ok := runner.build(d); ok {
			cfg.Devices = append(cfg.Devices, spec)
		}
	}
	runner.storeConfigured(devices)
	runner.pruneTombstones(devices)
	// The run.lock holder (reload set) idles with no device to run, until a
	// reload starts one or the run stops.
	if len(cfg.Devices) == 0 && reload == nil {
		return errNoDeviceStarts
	}

	mode := ui.DetectMode(noUI, os.Stderr)
	cfg.NoInspect = inspectDisabled(mode, false, false)
	a = agent.New(cfg)
	a.KeepIdle = reload != nil
	a.OnDeviceEnd = func(t *tunnel.Tunnel, err error) {
		runner.queueEnd(deviceEnd{identifier: t.Identity(), tunnel: t, err: err})
	}
	renderer := pickRenderer(mode, a)
	renderer.Banner(version, cfg)
	warnNoPortCeiling(renderer, cfg.Devices)
	defer renderer.Shutdown()

	ctx, stop := signalContext(func() {
		renderer.Shutdown()
		a.Stop()
	})
	defer stop()
	stopWithParent := context.AfterFunc(parent, func() {
		renderer.Shutdown()
		a.Stop()
		stop()
	})
	defer stopWithParent()

	// The uploader and the clipboard notice senders outlive the devices: they
	// stop after a.Run returns, so the final segments and notices of the
	// sessions the devices end are handed over first.
	var outliving []func(context.Context)
	if uploads != nil {
		outliving = append(outliving, uploads.Run)
	}
	outliving = append(outliving, runner.notices.Run)
	stopOutliving := runOutliving(outliving...)
	defer stopOutliving()
	var renewing sync.WaitGroup
	for _, s := range runner.served {
		s.start(ctx)
	}
	renewing.Go(func() { runner.watchReload(ctx, a, reload) })
	if devicesRunning != nil {
		devicesRunning()
	}
	if runnerServing != nil {
		runnerServing(runner, a)
	}
	runErr := a.Run(ctx, renderer)
	// Every device has stopped; end the reload, renewal and key refresh loops.
	stop()
	renewing.Wait()
	// Ends queued as the last tunnels stopped still forget or park.
	runner.handleEnds(context.WithoutCancel(ctx), a)
	for _, s := range runner.served {
		s.end()
	}
	runner.served = nil
	stopOutliving()
	renderer.Shutdown()
	// An edge refusal prints as its message and code (errcode.Render).
	return runErr
}

// runOutliving runs each of runs on its own goroutine with a context of its
// own, and returns the stop that cancels it and waits for every run to
// return; stop is idempotent.
func runOutliving(runs ...func(context.Context)) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for _, run := range runs {
		wg.Go(func() { run(ctx) })
	}
	return func() {
		cancel()
		wg.Wait()
	}
}

// errNoDeviceStarts means every listed device was skipped.
var errNoDeviceStarts = errcode.New(errcode.NoDeviceStarts)

// resolveEdge is the edge address of a device's region; tests point it at a
// local address so a served device dials no real edge.
var resolveEdge = config.ResolveEdge

// devicesRunning, when set, runs in serveDevices once every loop that
// outlives the devices has started, just before the devices run. Tests set
// it; nil otherwise.
var devicesRunning func()

// runnerServing, when set, receives the runner and agent where devicesRunning
// runs. Tests set it to queue device ends; nil otherwise.
var runnerServing func(*deviceRunner, *agent.Agent)

// deviceSpec builds the runtime spec of one enrolled device from its local
// config entry, its stored credential and the launcher probe. renews
// reports whether the credential renews itself.
func deviceSpec(store *identity.Store, d config.LocalDevice, probe sessionProbe, logEvent func(string)) (spec config.DeviceSpec, renews bool, err error) {
	m, err := store.Load(d.Identity)
	if err != nil {
		return config.DeviceSpec{}, false, fmt.Errorf("device %s: %w", d.Identity, err)
	}
	if m.Meta.Device == nil {
		return config.DeviceSpec{}, false, fmt.Errorf("device %s: the stored credential is not a device credential", d.Identity)
	}
	host := d.Host
	if host == "" {
		host = config.DefaultDeviceHost
	}
	capabilities := make([]string, len(d.Enable))
	for i, c := range d.Enable {
		capabilities[i] = string(c)
	}
	var desktop []string
	var vncTarget, rdpTarget string
	if slices.Contains(d.Enable, config.CapabilityDesktop) {
		for _, target := range []struct{ kind, value string }{{"rdp", d.RDP}, {"vnc", d.VNC}} {
			if target.value != "" {
				desktop = append(desktop, target.kind)
			}
		}
		vncTarget, rdpTarget = d.VNC, d.RDP
	}
	// The edge names the device by the prefix in its certificate; the
	// client name only labels it in this agent's output.
	_, prefix, _ := strings.Cut(d.Identity.Identity, ".")
	logins := d.Logins
	if d.RunAsAgent && d.UsesLogins() {
		// The session mint checks the login against the reported list.
		logins = []string{launcher.AgentAccount}
	}
	spec = config.DeviceSpec{
		Name:           prefix,
		Identity:       d.Identity.Identity,
		Host:           host,
		Edge:           resolveEdge(m.Meta.Device.Region),
		AllowPorts:     d.AllowPorts,
		Credential:     identity.NewDeviceRegistrar(store, d.Identity, logEvent),
		Capabilities:   capabilities,
		Logins:         logins,
		PasswordLogins: d.PasswordLogins,
		Desktop:        desktop,
		VNCTarget:      vncTarget,
		RDPTarget:      rdpTarget,
		RunAsAgent:     d.RunAsAgent,
	}
	if d.UsesLogins() {
		spec.SessionAuth = probe.sessionAuth
	}
	return spec, m.Meta.Source.Renewable(), nil
}

// deviceSessionState is what serving one device's sessions holds for the run:
// the refresher that keeps its CA keys current and its sessions lock.
type deviceSessionState struct {
	refresher *identity.KeyRefresher
	lock      *session.SessionsLock
	// unshare releases the store lock's shared hold taken for lock; it runs
	// after lock is closed.
	unshare func()
}

// deviceSessions sets spec's HintRevoked hook and, when the device enables a
// session capability, its session server. The server binds certificates to,
// and uses as SSH host key, the last acknowledged registration's certificate
// (spec.Credential), never Store.Load, which lags behind a renewal until it is
// promoted. It returns nil state when no server is set. It returns an error,
// leaving sessions off, when the sessions lock is held elsewhere (another
// process serves the identity) or the device has logins and this process is
// not an account the session launcher serves.
func deviceSessions(store *identity.Store, ref identity.Ref, spec *config.DeviceSpec, uploads *recording.Uploader, notices *tunnel.ClipboardNotices, logEvent func(string)) (*deviceSessionState, error) {
	keys, err := store.TicketKeys(ref)
	if err != nil {
		return nil, err
	}
	// Loaded once, here, before the hook is set, so a hint in the first
	// RegisterAck finds the held set. An unreadable file leaves the set empty;
	// the refresher, where one runs, fetches at once and reports the remedy.
	switch err := keys.Load(); {
	case errors.Is(err, identity.ErrRecordingKeyDropped):
		logEvent(fmt.Sprintf("identity: %s: %v; the next key fetch or renewal stores it again", ref, err))
	case err != nil:
		logEvent(fmt.Sprintf("identity: cannot read the session keys of %s: %v", ref, err))
	}
	if len(spec.Capabilities) == 0 || spec.Credential == nil {
		spec.HintRevoked = hintRevoked(keys, nil, logEvent)
		return nil, nil
	}
	// A test's launcher replaces the one whose account check this mirrors.
	if sessionLauncher == nil && len(spec.Logins) > 0 {
		if err := checkSessionAccount(); err != nil {
			spec.HintRevoked = hintRevoked(keys, nil, logEvent)
			return nil, err
		}
	}
	// The sessions lock lives in the credential's lock directory, held under a
	// shared hold of the store lock for as long as the lock is.
	unshare, err := store.ShareStore(context.Background())
	if err != nil {
		spec.HintRevoked = hintRevoked(keys, nil, logEvent)
		return nil, err
	}
	lockDir, err := store.LockDir(ref)
	var lock *session.SessionsLock
	if err == nil {
		lock, err = session.LockSessions(lockDir)
	}
	if err != nil {
		unshare()
		spec.HintRevoked = hintRevoked(keys, nil, logEvent)
		return nil, err
	}
	// A device ref always has a pin store; without one every desktop
	// handshake that needs it ends desktop_key_unavailable.
	var desktopKeys session.DesktopKeys
	if pins, err := store.DesktopPins(ref); err == nil {
		desktopKeys = pins
	} else {
		logEvent(fmt.Sprintf("identity: no desktop key store for %s: %v", ref, err))
	}
	refresher := &identity.KeyRefresher{Store: store, Ref: ref, OnEvent: logEvent}
	spec.HintRevoked = hintRevoked(keys, refresher, logEvent)
	spec.SessionHandler = session.NewServer(session.ServerConfig{
		Prefix:         spec.Name,
		Certificate:    spec.Credential.RegisteredCertificate,
		CAKeys:         keys.CAKeys,
		RefreshKeys:    refresher.RefreshNow,
		RecordingKey:   keys.RecordingKey,
		Capabilities:   spec.Capabilities,
		Logins:         spec.Logins,
		PasswordLogins: spec.PasswordLogins,
		Desktop:        spec.Desktop,
		VNCTarget:      spec.VNCTarget,
		RDPTarget:      spec.RDPTarget,
		DesktopKeys:    desktopKeys,
		OnEvent:        logEvent,
		OnClipboard:    clipboardReporter(notices, ref.Identity),
		Uploader:       uploads,
		Identifier:     ref.Identity,
		Device:         ref.String(),
		Launcher:       sessionLauncher,
		// nil-safe: a device without logins has no state.
		OnFullDiskAccess: spec.FullDiskAccess.Set,
	})
	spec.ClipboardNotices = notices
	return &deviceSessionState{refresher: refresher, lock: lock, unshare: unshare}, nil
}

// clipboardReporter queues a device's clipboard decisions on notices; nil
// when notices is nil.
func clipboardReporter(notices *tunnel.ClipboardNotices, identifier string) func(session.ClipboardDecision) {
	if notices == nil {
		return nil
	}
	return func(d session.ClipboardDecision) { notices.Note(identifier, tunnel.ClipboardNotice(d)) }
}

// hintRevoked returns the HintRevoked hook of one device: the edge's revoked
// kids become hints, and a hint on a held kid asks refresher, when there is
// one, for a fetch from the control plane, which settles it.
func hintRevoked(keys *identity.TicketKeys, refresher *identity.KeyRefresher, logEvent func(string)) func([]string) {
	return func(kids []string) {
		added, err := keys.Hint(kids)
		if err != nil {
			logEvent(fmt.Sprintf("identity: ignored the revoked session key ids the edge sent: %v", err))
			return
		}
		if added && refresher != nil {
			refresher.Hint()
		}
	}
}

// openUploader opens the recording spool at <state root>/recordings, logs
// each entry the scan dropped, and returns the uploader with the spool's
// entries queued for resume. It returns nil, logged, when the spool cannot be
// opened: Best effort sessions then run unrecorded and Strict sessions are
// refused recording_unavailable.
func openUploader(store *identity.Store, configured func(identifier string) bool, client func(string) (recording.Client, error)) *recording.Uploader {
	root, followRoot := store.StateRoot()
	spool, scan, err := recording.OpenSpool(root, recordingSpoolDir(store), followRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  recording disabled: %v\n", err)
		return nil
	}
	for _, d := range scan.Dropped {
		slog.Warn("recording spool entry dropped", slog.String("recording", d.ID), slog.String("path", d.Path), slog.Any("error", d.Err))
	}
	u := recording.NewUploader(recording.UploaderConfig{
		Spool:      spool,
		Client:     client,
		Configured: configured,
	})
	u.Resume(scan)
	return u
}

// recordingSpoolDir is the recording spool directory of store's state root.
func recordingSpoolDir(store *identity.Store) string {
	root, _ := store.StateRoot()
	return filepath.Join(root, "recordings")
}

// deviceRecordingClient returns the recording client of the running device
// tunnel of identifier, or recording.ErrNoSessionMux when identifier has no
// running device tunnel.
func deviceRecordingClient(a *agent.Agent, identifier string) (recording.Client, error) {
	t := deviceTunnel(a.Tunnels(), identifier)
	if t == nil {
		return nil, recording.ErrNoSessionMux
	}
	c, err := t.RecordingClient()
	if err != nil {
		return nil, err
	}
	return c, nil
}

// deviceClipboardClient returns the clipboard notice client of the running
// device tunnel of identifier, or tunnel.ErrNoClipboardClient.
func deviceClipboardClient(a *agent.Agent, identifier string) (*tunnel.ClipboardClient, error) {
	t := deviceTunnel(a.Tunnels(), identifier)
	if t == nil {
		return nil, tunnel.ErrNoClipboardClient
	}
	return t.ClipboardClient()
}

// deviceTunnel returns the device tunnel in tunnels whose identity is
// identifier, or nil. Labels hold only the prefix, which repeats across fleets.
func deviceTunnel(tunnels []*tunnel.Tunnel, identifier string) *tunnel.Tunnel {
	for _, t := range tunnels {
		if t.IsDevice() && t.Identity() == identifier {
			return t
		}
	}
	return nil
}

func usageRun() {
	fmt.Fprint(os.Stderr, `Usage: localport run [--noui] [--system | --service] [--log-file PATH]

  Run every device enrolled on this machine, as listed in the local config:
  /etc/localport-device/agent.yaml (Linux), /Library/Application Support/
  localport-device/agent.yaml (macOS) or %ProgramData%\localport-device\
  agent.yaml (Windows) as root or Administrator, otherwise
  $LOCALPORT_HOME/agent.yaml (default ~/.localport/agent.yaml). Credentials
  live in the identity directory beside it. Each device credential renews
  itself. A device whose credential is missing or unreadable is skipped.
  The device service runs it with --service. As root (Administrator), only
  one process serves the machine-wide devices: run holds run.lock in the
  config directory while it runs and is refused at once while another
  process holds it, naming the device service when it is installed. As root
  the binary must also be replaceable only by root or Administrators.

Flags:
  --noui      disable the live view and emit plain logs
  --system    serve the machine-wide config and credentials; needs root or an
              elevated Administrator (AG159 otherwise)
  --service   run as the installed device service: implies --system, and
              waits for run.lock while a restarting service stops or a
              foreground run serves the devices, then serves them
  --log-file  write stdout and stderr to PATH and rotate it by size (Linux
              and macOS; the launchd and OpenRC definitions pass it)

  With --service on Linux and macOS, SIGHUP (the service manager's reload)
  re-reads the local config and restarts only the devices whose entry
  changed, was added or was removed; their open sessions end with
  config_changed. A config that fails to load keeps the running devices.
  A privileged run without --service reloads the same way when up, down or
  set asks it through its control endpoint (root or elevated Administrators
  only), and keeps running with no device to serve.
`)
}

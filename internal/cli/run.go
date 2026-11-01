package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
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
	"github.com/localport/agent/internal/tunnel"
	"github.com/localport/agent/internal/ui"
)

// runRun runs every device enrolled in the local config. Every generated
// service definition runs it with --service. Started by the Windows service
// control manager, it runs under the manager's control loop and stops when
// the manager stops the service.
func runRun(version string, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	noUI := fs.Bool("noui", false, "disable the live view and emit plain logs (auto-enabled when stderr is not a TTY)")
	system := fs.Bool("system", false, "use the machine-wide config and credentials whatever the account")
	asService := fs.Bool("service", false, "run as the installed device service (implies --system)")
	logFile := fs.String("log-file", "", "write stdout and stderr to this file and rotate it (launchd, OpenRC)")
	fs.Usage = usageRun
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		usageRun()
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
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
	if underSCM, err := service.RunUnderSCM(func(ctx context.Context, running func()) error {
		return runEnrolledDevices(ctx, version, who, *asService, true, running)
	}); underSCM || err != nil {
		return err
	}
	return runEnrolledDevices(context.Background(), version, who, *asService, *noUI, func() {})
}

// runEnrolledDevices loads the local config and serves its devices. A
// privileged process first re-checks that only root or Administrators can
// replace its binary, then holds run.lock until it returns (see
// holdRunLock); the config is loaded only once the lock is held. running is
// called after the binary check, before the run.lock wait.
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
	if who.privileged {
		release, err := holdRunLock(ctx, file, "localport run", asService)
		if err != nil {
			return err
		}
		defer func() { retErr = errors.Join(retErr, release()) }()
	}
	cfg, err := config.LoadLocal(file)
	if err != nil {
		return err
	}
	store, err := who.store()
	if err != nil {
		return err
	}
	// Only the service reloads on SIGHUP: a run in a terminal keeps ending on
	// the terminal's hangup.
	var reload func() ([]config.LocalDevice, error)
	if asService {
		reload = func() ([]config.LocalDevice, error) {
			cfg, err := config.LoadLocal(file)
			if err != nil {
				return nil, err
			}
			return cfg.Devices, nil
		}
	}
	return serveDevices(ctx, version, store, cfg.Devices, noUI, false, reload)
}

// serveDevices runs the enrolled devices until a signal or until parent ends,
// with the renewal loop of each renewable device credential. A device whose
// credential is missing or unreadable is logged and skipped; it refuses to
// start when no device can. noMux serves every inbound connection over its
// own connection, so the devices serve no sessions. With reload set, each
// reload signal (SIGHUP on Unix) re-reads the devices through it and applies
// the changed ones only (deviceRunner.reload).
func serveDevices(parent context.Context, version string, store *identity.Store, devices []config.LocalDevice, noUI, noMux bool, reload func() ([]config.LocalDevice, error)) error {
	logEvent := func(line string) { fmt.Fprintf(os.Stderr, "  [identity] %s\n", line) }
	cfg := &config.Config{AgentVersion: version, NoMux: noMux}
	var a *agent.Agent
	runner := &deviceRunner{parent: parent, store: store, logEvent: logEvent, served: map[identity.Ref]*servedDevice{}}
	runner.configured.Store(&devices)
	// The uploader runs only after a is set.
	runner.uploads = openUploader(store, runner.isConfigured, func(identifier string) (recording.Client, error) {
		return deviceRecordingClient(a, identifier)
	})
	uploads := runner.uploads
	// With noMux no session runs, so the launcher is not probed.
	runner.probed = noMux
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
	if len(cfg.Devices) == 0 {
		return errNoDeviceStarts
	}

	mode := ui.DetectMode(noUI, os.Stderr)
	cfg.NoInspect = inspectDisabled(mode, false, false)
	a = agent.New(cfg)
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

	// The uploader outlives the devices: it stops after a.Run returns, so the
	// final segments of the sessions the devices end are handed over first.
	upCtx, stopUploads := context.WithCancel(context.Background())
	defer stopUploads()
	var renewing sync.WaitGroup
	if uploads != nil {
		renewing.Go(func() { uploads.Run(upCtx) })
	}
	for _, s := range runner.served {
		s.start(ctx)
	}
	if reload != nil {
		renewing.Go(func() { runner.watchReload(ctx, a, reload) })
	}
	runErr := a.Run(ctx, renderer)
	// Every device has stopped; end the reload, renewal and key refresh loops
	// with them.
	stop()
	renewing.Wait()
	for _, s := range runner.served {
		s.end()
	}
	runner.served = nil
	stopUploads()
	renderer.Shutdown()

	var regErr *tunnel.RegistrationError
	if errors.As(runErr, &regErr) && regErr.Code != "" {
		return fmt.Errorf("%s [%s]", regErr.Error(), regErr.Code)
	}
	return runErr
}

// errNoDeviceStarts means every listed device was skipped.
var errNoDeviceStarts = errcode.New(errcode.NoDeviceStarts)

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
	if slices.Contains(d.Enable, config.CapabilityDesktop) {
		for _, target := range []struct{ kind, value string }{{"rdp", d.RDP}, {"vnc", d.VNC}} {
			if target.value != "" {
				desktop = append(desktop, target.kind)
			}
		}
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
		Name:         prefix,
		Identity:     d.Identity.Identity,
		Host:         host,
		Edge:         config.ResolveEdge(m.Meta.Device.Region),
		AllowPorts:   d.AllowPorts,
		Credential:   identity.NewDeviceRegistrar(store, d.Identity, logEvent),
		Capabilities: capabilities,
		Logins:       logins,
		Desktop:      desktop,
		RunAsAgent:   d.RunAsAgent,
	}
	if d.UsesLogins() {
		spec.SessionAuth, spec.FullDiskAccess = probe.sessionAuth, probe.fullDiskAccess
	}
	return spec, m.Meta.Source.Renewable(), nil
}

// deviceSessionState is what serving one device's sessions holds for the run:
// the refresher that keeps its ticket keys current and its jti log.
type deviceSessionState struct {
	refresher *identity.KeyRefresher
	jti       *session.JTILog
}

// deviceSessions sets spec's HintRevoked hook and, when the device enables a
// session capability, its session server. The server checks tickets against
// and signs with the certificate of the last acknowledged registration
// (spec.Credential), never Store.Load, which lags behind a renewed
// certificate until it is promoted. It returns nil state when no server is
// set, and an error, leaving sessions off, when the jti log cannot be held,
// as when another process serves the same identity.
func deviceSessions(store *identity.Store, ref identity.Ref, spec *config.DeviceSpec, uploads *recording.Uploader, logEvent func(string)) (*deviceSessionState, error) {
	keys, err := store.TicketKeys(ref)
	if err != nil {
		return nil, err
	}
	// Loaded once, here, before the hook is set, so a hint in the first
	// RegisterAck finds the held set. An unreadable file leaves the set empty;
	// the refresher, where one runs, fetches at once and reports the remedy.
	if err := keys.Load(); err != nil {
		logEvent(fmt.Sprintf("identity: cannot read the ticket keys of %s: %v", ref, err))
	}
	if len(spec.Capabilities) == 0 || spec.Credential == nil {
		spec.HintRevoked = hintRevoked(keys, nil, logEvent)
		return nil, nil
	}
	jti, err := session.OpenJTILog(store.Dir(ref), nil)
	if err != nil {
		spec.HintRevoked = hintRevoked(keys, nil, logEvent)
		return nil, err
	}
	refresher := &identity.KeyRefresher{Store: store, Ref: ref, OnEvent: logEvent}
	spec.HintRevoked = hintRevoked(keys, refresher, logEvent)
	spec.SessionHandler = session.NewServer(session.ServerConfig{
		Prefix:       spec.Name,
		Certificate:  spec.Credential.RegisteredCertificate,
		Lookup:       keys.Lookup,
		RefreshKeys:  refresher.RefreshNow,
		RecordingKey: keys.RecordingKey,
		Capabilities: spec.Capabilities,
		Logins:       spec.Logins,
		Desktop:      spec.Desktop,
		JTI:          jti,
		OnEvent:      logEvent,
		Uploader:     uploads,
		Identifier:   ref.Identity,
		Device:       ref.String(),
		Launcher:     sessionLauncher,
	})
	return &deviceSessionState{refresher: refresher, jti: jti}, nil
}

// hintRevoked returns the HintRevoked hook of one device: the edge's revoked
// kids become hints, and a hint on a held kid asks refresher, when there is
// one, for a fetch from the control plane, which settles it.
func hintRevoked(keys *identity.TicketKeys, refresher *identity.KeyRefresher, logEvent func(string)) func([]string) {
	return func(kids []string) {
		added, err := keys.Hint(kids)
		if err != nil {
			logEvent(fmt.Sprintf("identity: ignored the revoked ticket keys the edge sent: %v", err))
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
  --system    use the machine-wide config and credentials whatever the account
  --service   run as the installed device service: implies --system, and
              waits up to 30 s for run.lock while a restarting service stops
  --log-file  write stdout and stderr to PATH and rotate it by size (Linux
              and macOS; the launchd and OpenRC definitions pass it)

  With --service on Linux and macOS, SIGHUP (the service manager's reload)
  re-reads the local config and restarts only the devices whose entry
  changed, was added or was removed; their open sessions end with
  config_changed. A config that fails to load keeps the running devices.
`)
}

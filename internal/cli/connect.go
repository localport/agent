package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/localport/agent/internal/agent"
	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/security"
	"github.com/localport/agent/internal/service"
	"github.com/localport/agent/internal/tunnel"
	"github.com/localport/agent/internal/ui"
)

// runConnect joins this machine to a fleet as one device, or runs every tunnel
// and device in a config file. Device ports come from the dashboard.
func runConnect(version string, args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		configPath  = fs.String("config", "", "path to YAML config")
		token       = fs.String("token", "", "fleet token")
		region      = fs.String("region", "", "edge region: eu, us, ap")
		name        = fs.String("name", "", "device name (default: this machine's hostname)")
		host        = fs.String("host", "", "where this device sends traffic (default: localhost)")
		allowPorts  = fs.String("allow-ports", "", "limit which ports this device serves, e.g. 502,80,8000-8100 (default: any port the dashboard allows)")
		noUI        = fs.Bool("noui", false, "disable the live view and emit plain logs (auto-enabled when stderr is not a TTY)")
		noMux       = fs.Bool("no-mux", false, "send each inbound connection over its own connection instead of multiplexing them")
		noInspect   = fs.Bool("no-inspect", false, "do not inspect HTTP requests")
		logRequests = fs.Bool("log-requests", false, "log one line per HTTP request in headless mode (http ports)")
	)
	fs.StringVar(token, "t", "", "alias for --token")
	fs.Usage = func() { usageConnect(fs) }

	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := refuseBesideConfig(fs, *configPath, "token", "t", "region", "name", "host", "allow-ports"); err != nil {
		return err
	}

	cfg, err := buildConnectConfig(*configPath, *token, *region, *name, *host, *allowPorts)
	if err != nil {
		fs.Usage()
		return err
	}
	if *noMux {
		cfg.NoMux = true
	}
	cfg.AgentVersion = version

	mode := ui.DetectMode(*noUI, os.Stderr)
	cfg.NoInspect = inspectDisabled(mode, *noInspect, *logRequests)

	a := agent.New(cfg)
	renderer := pickRenderer(mode, a)
	renderer.Banner(version, cfg)
	warnTokenFlag(renderer, *configPath == "" && strings.TrimSpace(*token) != "")
	warnNoPortCeiling(renderer, cfg.Devices)
	defer renderer.Shutdown()

	// Stop ends all sessions at once. The renderer shuts down first to
	// restore the terminal before teardown output.
	ctx, stop := signalContext(func() {
		renderer.Shutdown()
		a.Stop()
	})
	defer stop()

	runErr := a.Run(ctx, renderer)
	renderer.Shutdown()

	var regErr *tunnel.RegistrationError
	if errors.As(runErr, &regErr) && regErr.Code != "" {
		return fmt.Errorf("%s [%s]", regErr.Error(), regErr.Code)
	}
	return runErr
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
		return nil, fmt.Errorf("%w; the device service %s is installed: use it, or stop it before %s", err, m.Name(), command)
	}
	return nil, fmt.Errorf("%w; another localport run or connect --foreground serves them", err)
}

// unsafeBinaryRemedy follows a security.ErrUnsafeExecutable refusal.
const unsafeBinaryRemedy = `install localport into a directory only root or Administrators can write, then call it by its absolute path: run the install script under sudo (it installs to /usr/local/bin, or /opt/localport/bin when /usr/local/bin is not root-owned) and use sudo /usr/local/bin/localport connect ..., or run install.ps1 elevated and use & "$env:ProgramFiles\Localport\localport.exe" connect ...; a Homebrew, Scoop, winget or user-profile install cannot run the device service`

// serviceExecutable is the resolved running binary, refused unless only root
// or Administrators can replace it.
func serviceExecutable() (string, error) {
	exe, err := service.Executable()
	if err != nil {
		return "", err
	}
	if err := checkServiceBinary(exe); err != nil {
		return "", fmt.Errorf("%w\n  %s", err, unsafeBinaryRemedy)
	}
	return exe, nil
}

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

func buildConnectConfig(path, flagToken, region, name, host, allowPorts string) (*config.Config, error) {
	if path != "" {
		return config.Load(path)
	}
	token, err := security.ResolveToken(flagToken, "LOCALPORT_TOKEN")
	if err != nil {
		return nil, err
	}
	if name == "" {
		host, _ := os.Hostname()
		name = config.DefaultDeviceName(host)
	}
	if name == "" {
		return nil, errors.New("--name is required, because this machine reports no usable hostname")
	}
	return config.DeviceFromFlags(token, region, name, host, allowPorts)
}

func usageConnect(fs *flag.FlagSet) {
	fmt.Fprint(os.Stderr, `Usage: localport connect -t <token> [--name <device>] [--host <address>]
       localport connect --config localport.yaml

  Join a fleet as one device. The ports this device serves are set in the
  dashboard, and consumers reach them with:

    localport access <device-host> -L <local>:<remote>

  One device, named after this machine:
    localport connect -t <token>

  One device, serving another machine on this network:
    localport connect -t <token> --name plc-01 --host 192.168.1.100

  One device that serves only the listed ports:
    localport connect -t <token> --allow-ports 502,80,8000-8100

  Every tunnel and device in a file. The file sets them all, so --token,
  --region, --name, --host and --allow-ports are refused beside it:
    localport connect --config localport.yaml

Environment:
  LOCALPORT_TOKEN        fleet token (alternative to --token)
  LOCALPORT_TOKEN_FILE   file to read the token from, for systemd LoadCredential=
                         and docker secrets
  NO_COLOR               disable colored output

Flags:
`)
	fs.PrintDefaults()
}

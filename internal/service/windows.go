//go:build windows

package service

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/localport/agent/internal/security"
)

// WindowsName is the device service's name in the service control manager.
const WindowsName = security.WindowsServiceName

// windowsAccount is the service's virtual account: its own SID and no
// password, a member of Users, not of Administrators. Its token holds only
// serviceRequiredPrivileges; without that list it would also hold
// SeImpersonatePrivilege and SeCreateGlobalPrivilege.
const windowsAccount = `NT SERVICE\` + WindowsName

// serviceRequiredPrivileges is the service's required privileges list. The
// service control manager removes every other privilege from its token.
var serviceRequiredPrivileges = []string{"SeChangeNotifyPrivilege"}

// changeServiceConfig2 is windows.ChangeServiceConfig2; tests replace it.
var changeServiceConfig2 = windows.ChangeServiceConfig2

// serviceRequiredPrivilegesInfo is SERVICE_REQUIRED_PRIVILEGES_INFO, which
// x/sys does not define: a REG_MULTI_SZ list of privilege names.
type serviceRequiredPrivilegesInfo struct {
	requiredPrivileges *uint16
}

// setRequiredPrivileges sets the required privileges list of service h.
func setRequiredPrivileges(h windows.Handle, privileges []string) error {
	var multi []uint16
	for _, p := range privileges {
		u, err := windows.UTF16FromString(p)
		if err != nil {
			return err
		}
		multi = append(multi, u...)
	}
	multi = append(multi, 0)
	info := serviceRequiredPrivilegesInfo{requiredPrivileges: &multi[0]}
	return changeServiceConfig2(h, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, (*byte)(unsafe.Pointer(&info)))
}

// servicePreshutdownInfo is SERVICE_PRESHUTDOWN_INFO, which x/sys does not
// define: the preshutdown timeout in milliseconds.
type servicePreshutdownInfo struct {
	preshutdownTimeout uint32
}

// setPreshutdownTimeout sets how long the service control manager waits for
// service h to stop after SERVICE_CONTROL_PRESHUTDOWN.
func setPreshutdownTimeout(h windows.Handle, timeout time.Duration) error {
	info := servicePreshutdownInfo{preshutdownTimeout: uint32(timeout / time.Millisecond)}
	return changeServiceConfig2(h, windows.SERVICE_CONFIG_PRESHUTDOWN_INFO, (*byte)(unsafe.Pointer(&info)))
}

// windowsDescription carries Marker, the Windows form of a marker line.
const windowsDescription = "Localport fleet device agent. " + Marker

// Default is the Windows service control manager.
func Default() (Manager, error) { return scm{}, nil }

// scm manages the device service through the service control manager.
type scm struct{}

func (scm) Name() string { return WindowsName }

// open runs fn on the device service, or with nil when it does not exist.
func (scm) open(fn func(*mgr.Mgr, *mgr.Service) error) error {
	m, err := mgr.Connect()
	if err != nil {
		return errManager.With(err, "connect to the service control manager")
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(WindowsName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return fn(m, nil)
	}
	if err != nil {
		return errManager.With(err, "open service "+WindowsName)
	}
	defer s.Close()
	return fn(m, s)
}

// ownedService refuses a service under name this package did not create,
// and returns its configuration.
func ownedService(name string, s interface{ Config() (mgr.Config, error) }) (mgr.Config, error) {
	cfg, err := s.Config()
	if err != nil {
		return cfg, errManager.With(err, "read service "+name)
	}
	if !strings.Contains(cfg.Description, Marker) {
		return cfg, ErrForeignUnit.With(nil, fmt.Sprintf("Windows service %q; remove it (sc.exe delete %s), then run the command again", name, name))
	}
	return cfg, nil
}

// Check refuses a foreign service under the device or the launcher service
// name, and a launcher service deleted but still held, before anything is
// spent; Installed reports the device service's own state.
func (c scm) Check() ([]string, error) {
	for _, name := range []string{WindowsName, LauncherName} {
		if err := openService(name, func(_ *mgr.Mgr, s *mgr.Service) error {
			if s == nil {
				return nil
			}
			if _, err := ownedService(name, s); err != nil {
				return err
			}
			if name == LauncherName {
				return checkNotMarkedForDelete(name, scmService{s})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// Installed returns true with ErrMarkedForDelete for a deleted service that
// a handle still holds.
func (c scm) Installed() (bool, error) {
	installed := false
	err := c.open(func(_ *mgr.Mgr, s *mgr.Service) error {
		if s == nil {
			return nil
		}
		var err error
		installed, err = installedState(scmService{s})
		return err
	})
	return installed, err
}

// installedState judges an existing service: ErrForeignUnit when this
// package did not create it, true with ErrMarkedForDelete when it is
// deleted but still held, and true otherwise.
func installedState(s interface {
	Config() (mgr.Config, error)
	ChangeNothing() error
}) (bool, error) {
	if _, err := ownedService(WindowsName, s); err != nil {
		return false, err
	}
	return true, checkNotMarkedForDelete(WindowsName, s)
}

// ChangeNothing calls ChangeServiceConfig with no change. It fails with
// ERROR_SERVICE_MARKED_FOR_DELETE for a deleted service that a handle
// still holds, since such a service refuses every change.
func (s scmService) ChangeNothing() error {
	ns := uint32(windows.SERVICE_NO_CHANGE)
	return windows.ChangeServiceConfig(s.Handle, ns, ns, ns, nil, nil, nil, nil, nil, nil, nil)
}

// checkNotMarkedForDelete returns ErrMarkedForDelete for a deleted service
// that a handle still holds.
func checkNotMarkedForDelete(name string, s interface{ ChangeNothing() error }) error {
	if err := s.ChangeNothing(); err != nil {
		return markedForDelete(errManager.With(err, "read service "+name))
	}
	return nil
}

// markedForDelete maps ERROR_SERVICE_MARKED_FOR_DELETE to ErrMarkedForDelete
// with its remedy, and returns any other error unchanged.
func markedForDelete(err error) error {
	if errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return ErrMarkedForDelete.With(nil, "close the Services console, Event Viewer and any other tool showing the service, or restart Windows, then run the command again")
	}
	return err
}

// MainPID is the process ID the service control manager reports
// (QueryServiceStatusEx) while the service is running, and 0 in any other
// state or when the service does not exist.
func (c scm) MainPID(context.Context) (int, error) {
	pid := 0
	err := c.open(func(_ *mgr.Mgr, s *mgr.Service) error {
		if s == nil {
			return nil
		}
		status, err := s.Query()
		if err != nil {
			return errManager.With(err, "query service "+WindowsName)
		}
		if status.State == svc.Running {
			pid = int(status.ProcessId)
		}
		return nil
	})
	return pid, err
}

// registerEventSource registers name as an Event Log source unless it is
// registered already.
func registerEventSource(name string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\EventLog\Application\`+name, registry.QUERY_VALUE)
	if err == nil {
		k.Close()
		return nil
	}
	if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return errManager.With(err, "read event log source "+name)
	}
	if err := eventlog.InstallAsEventCreate(name, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		return errManager.With(err, "register event log source "+name)
	}
	return nil
}

func removeEventSource(name string) error {
	if err := eventlog.Remove(name); err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return errManager.With(err, "remove event log source "+name)
	}
	return nil
}

// winService is the part of a service control manager service the install,
// restart and stop paths use. scmService implements it; tests fake it.
type winService interface {
	Config() (mgr.Config, error)
	UpdateConfig(mgr.Config) error
	SetRequiredPrivileges(privileges []string) error
	SetPreshutdownTimeout(timeout time.Duration) error
	SetRecoveryActions(actions []mgr.RecoveryAction, resetPeriod uint32) error
	SetRecoveryActionsOnNonCrashFailures(flag bool) error
	Query() (svc.Status, error)
	Control(c svc.Cmd) (svc.Status, error)
	Start(args ...string) error
}

// scmService adds the required privileges and preshutdown calls x/sys lacks
// to *mgr.Service.
type scmService struct{ *mgr.Service }

func (s scmService) SetRequiredPrivileges(privileges []string) error {
	return setRequiredPrivileges(s.Handle, privileges)
}

func (s scmService) SetPreshutdownTimeout(timeout time.Duration) error {
	return setPreshutdownTimeout(s.Handle, timeout)
}

// LauncherName is the session launcher service: localport-session.exe
// launcher as LocalSystem. It has no dependency on the device service, so
// stopping either leaves the other, and running sessions, alone.
const LauncherName = "localport-session"

// launcherRequiredPrivileges are the only privileges the launcher service
// keeps: S4U logon registration, assigning a primary token, quotas, and
// loading user profile hives.
var launcherRequiredPrivileges = []string{"SeTcbPrivilege", "SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege", "SeBackupPrivilege", "SeRestorePrivilege"}

// serviceDef is one service the device install registers.
type serviceDef struct {
	name, display, description, account string
	exe                                 string
	args                                []string
	privileges                          []string
	// preshutdown, when non-zero, is the preshutdown timeout. Only the agent
	// has one: it ends its sessions during preshutdown, before the launcher
	// gets SERVICE_CONTROL_SHUTDOWN.
	preshutdown time.Duration
}

func agentDef(exe string) serviceDef {
	return serviceDef{name: WindowsName, display: "Localport device", description: windowsDescription, account: windowsAccount,
		exe: exe, args: []string{"run", "--service"}, privileges: serviceRequiredPrivileges, preshutdown: StopBudget}
}

func launcherDef(exe string) serviceDef {
	return serviceDef{name: LauncherName, display: "Localport session launcher", description: "Localport session launcher. " + Marker, account: "LocalSystem",
		exe: SessionExecutable(exe), args: []string{"launcher"}, privileges: launcherRequiredPrivileges}
}

// Install registers or updates the session launcher service, then the
// device service, and (re)starts both.
func (c scm) Install(ctx context.Context, exe string) error {
	launcher := launcherDef(exe)
	if err := security.CheckServiceBinary(launcher.exe); err != nil {
		return err
	}
	for _, d := range []serviceDef{launcher, agentDef(exe)} {
		if err := registerEventSource(d.name); err != nil {
			return err
		}
		if err := openService(d.name, func(m *mgr.Mgr, s *mgr.Service) error {
			var existing winService
			if s != nil {
				existing = scmService{s}
			}
			return installDefinition(ctx, d, existing, func(want mgr.Config) (winService, func(), error) {
				created, err := m.CreateService(d.name, d.exe, want, d.args...)
				if err != nil {
					return nil, nil, err
				}
				return scmService{created}, func() { created.Close() }, nil
			})
		}); err != nil {
			return err
		}
	}
	return nil
}

// openService runs fn on service name, or with nil when it does not exist.
func openService(name string, fn func(*mgr.Mgr, *mgr.Service) error) error {
	m, err := mgr.Connect()
	if err != nil {
		return errManager.With(err, "connect to the service control manager")
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return fn(m, nil)
	}
	if err != nil {
		return errManager.With(err, "open service "+name)
	}
	defer s.Close()
	return fn(m, s)
}

// installService installs the device service for exe; see installDefinition.
func installService(ctx context.Context, exe string, existing winService, create func(mgr.Config) (winService, func(), error)) error {
	return installDefinition(ctx, agentDef(exe), existing, create)
}

// installDefinition creates the service d through create when existing is
// nil, otherwise rewrites existing's configuration, then sets its required
// privileges and recovery actions and (re)starts it.
func installDefinition(ctx context.Context, d serviceDef, existing winService, create func(mgr.Config) (winService, func(), error)) error {
	want := mgr.Config{
		DisplayName:      d.display,
		Description:      d.description,
		StartType:        mgr.StartAutomatic,
		ServiceStartName: d.account,
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}
	s := existing
	if s == nil {
		created, closeCreated, err := create(want)
		if err != nil {
			return markedForDelete(errManager.With(err, "create service "+d.name))
		}
		defer closeCreated()
		s = created
	} else {
		cfg, err := ownedService(d.name, s)
		if err != nil {
			return err
		}
		cfg.BinaryPathName = syscall.EscapeArg(d.exe)
		for _, a := range d.args {
			cfg.BinaryPathName += " " + syscall.EscapeArg(a)
		}
		cfg.DisplayName, cfg.Description = want.DisplayName, want.Description
		cfg.StartType, cfg.ServiceStartName, cfg.SidType = want.StartType, want.ServiceStartName, want.SidType
		if err := s.UpdateConfig(cfg); err != nil {
			return markedForDelete(errManager.With(err, "update service "+d.name))
		}
	}
	if err := s.SetRequiredPrivileges(d.privileges); err != nil {
		return errManager.With(err, "set required privileges of service "+d.name)
	}
	if d.preshutdown > 0 {
		if err := s.SetPreshutdownTimeout(d.preshutdown); err != nil {
			return errManager.With(err, "set preshutdown timeout of service "+d.name)
		}
	}
	// Restart on any exit, as systemd's Restart=always and launchd's
	// KeepAlive do; reset the failure count after a day.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second}}, 86400); err != nil {
		return errManager.With(err, "set recovery of service "+d.name)
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return errManager.With(err, "set recovery of service "+d.name)
	}
	return restart(ctx, d.name, s)
}

// Reload sends the device service SERVICE_CONTROL_PARAMCHANGE; it re-reads
// its config as SIGHUP does on Unix.
func (c scm) Reload(context.Context) error {
	return c.open(func(_ *mgr.Mgr, s *mgr.Service) error {
		if s == nil {
			return ErrNotInstalled
		}
		if _, err := s.Control(svc.ParamChange); err != nil {
			return errManager.With(err, "reload service "+WindowsName)
		}
		return nil
	})
}

func (c scm) Restart(ctx context.Context) error {
	return c.open(func(_ *mgr.Mgr, s *mgr.Service) error {
		if s == nil {
			return ErrNotInstalled
		}
		return restart(ctx, WindowsName, scmService{s})
	})
}

// Uninstall stops and deletes the device service and then the launcher service,
// and removes their Event Log sources, also when a service is already gone. It
// returns ErrNotInstalled when the device service was already gone.
func (c scm) Uninstall(ctx context.Context) error {
	var result error
	for _, name := range []string{WindowsName, LauncherName} {
		err := openService(name, func(_ *mgr.Mgr, s *mgr.Service) error {
			if s == nil {
				if name == WindowsName {
					result = ErrNotInstalled
				}
				return nil
			}
			if _, err := ownedService(name, s); err != nil {
				return err
			}
			if err := stop(ctx, name, scmService{s}); err != nil {
				return err
			}
			if err := s.Delete(); err != nil {
				return errManager.With(err, "delete service "+name)
			}
			return nil
		})
		if err != nil {
			return err
		}
		if err := removeEventSource(name); err != nil {
			return err
		}
	}
	return result
}

func restart(ctx context.Context, name string, s winService) error {
	if err := stop(ctx, name, s); err != nil {
		return err
	}
	if err := s.Start(); err != nil {
		return errManager.With(err, "start service "+name)
	}
	return nil
}

// stop asks the service to stop and waits until it has. The service
// control manager has no completion event in x/sys, so its state is polled.
func stop(ctx context.Context, name string, s winService) error {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	status, err := s.Query()
	if err != nil {
		return errManager.With(err, "query service "+name)
	}
	if status.State == svc.Stopped {
		return nil
	}
	if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return errManager.With(err, "stop service "+name)
	}
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return errManager.With(ctx.Err(), "stop service "+name)
		case <-tick.C:
		}
		status, err := s.Query()
		if err != nil {
			return errManager.With(err, "query service "+name)
		}
		switch status.State {
		case svc.Stopped:
			return nil
		case svc.Running:
			// A recovery action restarted the service during the wait.
			if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
				return errManager.With(err, "stop service "+name)
			}
		}
	}
}

// ownedServiceNames are the services the installer stops and starts around a
// commit, the launcher after the device service that uses it.
var ownedServiceNames = []string{WindowsName, LauncherName}

// StopOwned stops each owned service that is not stopped, waiting until it
// is, and returns the names it stopped. A service missing is skipped; one
// localport did not create under either name is refused.
func StopOwned(ctx context.Context) ([]string, error) {
	var stopped []string
	for _, name := range ownedServiceNames {
		err := openService(name, func(_ *mgr.Mgr, s *mgr.Service) error {
			if s == nil {
				return nil
			}
			if _, err := ownedService(name, s); err != nil {
				return err
			}
			status, err := s.Query()
			if err != nil {
				return errManager.With(err, "query service "+name)
			}
			if status.State == svc.Stopped {
				return nil
			}
			if err := stop(ctx, name, scmService{s}); err != nil {
				return err
			}
			stopped = append(stopped, name)
			return nil
		})
		if err != nil {
			return stopped, err
		}
	}
	return stopped, nil
}

// StartOwned starts names, or with none every owned service, the launcher
// first; a service already running or missing is skipped.
func StartOwned(names []string) error {
	if names == nil {
		names = ownedServiceNames
	}
	var errs []error
	for _, name := range []string{LauncherName, WindowsName} {
		if !slices.Contains(names, name) {
			continue
		}
		errs = append(errs, openService(name, func(_ *mgr.Mgr, s *mgr.Service) error {
			if s == nil {
				return nil
			}
			if _, err := ownedService(name, s); err != nil {
				return err
			}
			if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
				return errManager.With(err, "start service "+name)
			}
			return nil
		}))
	}
	return errors.Join(errs...)
}

// ForeignServicesIn lists the services localport did not create whose
// program is inside dir; uninstalling dir would break them.
func ForeignServicesIn(dir string) ([]string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, errManager.With(err, "connect to the service control manager")
	}
	defer func() { _ = m.Disconnect() }()
	names, err := m.ListServices()
	if err != nil {
		return nil, errManager.With(err, "list services")
	}
	var foreign []string
	for _, name := range names {
		s, err := m.OpenService(name)
		if err != nil {
			continue // a service deleted meanwhile, or one this account cannot read
		}
		cfg, err := s.Config()
		s.Close()
		if err != nil || strings.Contains(cfg.Description, Marker) {
			continue
		}
		if imageInside(cfg.BinaryPathName, dir) {
			foreign = append(foreign, name)
		}
	}
	return foreign, nil
}

// imageInside reports whether the program of the service command line cmd
// is inside dir. The program starts the line, after an opening quote when it
// is quoted. An unquoted line is matched as a whole, since its program can
// hold spaces (C:\Program Files\...) and the manager resolves it by trying
// each one. %VARS% are expanded and the \??\ prefix of a native path is
// dropped. Matching ignores case.
func imageInside(cmd, dir string) bool {
	cmd = strings.TrimPrefix(strings.TrimSpace(cmd), `"`)
	if expanded, err := registry.ExpandString(cmd); err == nil {
		cmd = expanded
	}
	cmd = strings.TrimPrefix(cmd, `\??\`)
	prefix := strings.TrimRight(filepath.Clean(dir), `\`) + `\`
	return len(cmd) >= len(prefix) && strings.EqualFold(cmd[:len(prefix)], prefix)
}

// RunUnderSCM reports whether the service control manager started this
// process and, when it did, runs serve under the manager's control loop
// until the manager stops the service or serve returns. serve does all the
// work, config loading included, so a failure is reported to the manager as
// a service-specific exit code rather than a start timeout (an ExitError's
// Code, else 1). The service reports START_PENDING until serve calls running
// and then SERVICE_RUNNING accepting Stop and Shutdown, which cancel serve's
// context. Standard error and the log package's output go to the Event Log
// under the source WindowsName while serve runs. The device service also
// accepts SERVICE_CONTROL_PARAMCHANGE, delivered on ParamChanges. Before
// serve, a fatal error of the previous run is kept and reported, and the Go
// runtime's fatal output goes to the service's crash directory (CrashDir).
// version is the agent version the crash report names.
func RunUnderSCM(version string, serve func(ctx context.Context, running func()) error) (bool, error) {
	return runUnderSCM(WindowsName, version, serve, notifyParamChange)
}

// RunLauncherUnderSCM is RunUnderSCM for the session launcher service.
func RunLauncherUnderSCM(version string, serve func(ctx context.Context, running func()) error) (bool, error) {
	return runUnderSCM(LauncherName, version, serve, nil)
}

// Event Log event IDs of crash capture.
const (
	eventCrashKept    = 3
	eventCrashWarning = 4
)

// CrashRoot is the directory holding each service's crash directory,
// %ProgramData%\localport-device\crash; "" when %ProgramData% is unset.
func CrashRoot() string {
	data := os.Getenv("ProgramData")
	if data == "" {
		return ""
	}
	return filepath.Join(data, "localport-device", "crash")
}

// CrashDir is the crash directory of the service name and whether the device
// service may write it: crash\device for the device service, crash\launcher
// (the device service has no access) for the session launcher.
func CrashDir(name string) (dir string, deviceService bool) {
	root := CrashRoot()
	if root == "" {
		return "", false
	}
	if name == LauncherName {
		return filepath.Join(root, "launcher"), false
	}
	return filepath.Join(root, "device"), true
}

func runUnderSCM(name, version string, serve func(ctx context.Context, running func()) error, paramChange func()) (bool, error) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return false, errManager.With(err, "detect the service control manager")
	}
	if !isService {
		return false, nil
	}
	h := &scmHandler{name: name, serve: serve, paramChange: paramChange, preshutdown: name == WindowsName}
	// Without the Event Log the service still runs; the manager records its
	// exit code.
	warn, report := func(string) {}, func(string) {}
	if elog, err := eventlog.Open(name); err == nil {
		defer elog.Close()
		h.log = elog
		warn = func(msg string) { _ = elog.Warning(eventCrashWarning, msg) }
		report = func(msg string) { _ = elog.Error(eventCrashKept, msg) }
		if restore, err := stderrToEventLog(elog); err == nil {
			defer restore()
		}
	}
	if dir, deviceService := CrashDir(name); dir != "" {
		captureCrashes(dir, name, version, func(d string) error { return security.CheckCrashDir(d, deviceService) }, warn, report)
	} else {
		warn(name + ": crash capture is off: %ProgramData% is not set")
	}
	if err := svc.Run(name, h); err != nil {
		return true, errManager.With(err, "run service "+name)
	}
	return true, h.err
}

// paramChanges carries one pending SERVICE_CONTROL_PARAMCHANGE as SIGHUP,
// the signal the Unix agent reloads on.
var paramChanges = make(chan os.Signal, 1)

// ParamChanges delivers each SERVICE_CONTROL_PARAMCHANGE the device service
// receives; changes that arrive while one is pending merge into it.
func ParamChanges() <-chan os.Signal { return paramChanges }

func notifyParamChange() {
	select {
	case paramChanges <- syscall.SIGHUP:
	default:
	}
}

// exitCode is the service-specific exit code for err: an ExitError's Code,
// else 1.
func exitCode(err error) uint32 {
	var exitErr *ExitError
	if errors.As(err, &exitErr) && exitErr.Code > 0 {
		return uint32(exitErr.Code)
	}
	return 1
}

// stderrToEventLog sends each line written to os.Stderr or through the log
// package (and so the default slog handler) to l until restore runs. restore
// puts both back and waits for the last line.
func stderrToEventLog(l *eventlog.Log) (restore func(), err error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	prev, prevLog := os.Stderr, log.Writer()
	os.Stderr = w
	log.SetOutput(w)
	done := make(chan struct{})
	go func() {
		defer close(done)
		lines := bufio.NewReader(r)
		for {
			line, err := lines.ReadString('\n')
			if line = strings.TrimSpace(line); line != "" {
				_ = l.Info(1, line)
			}
			if err != nil {
				return
			}
		}
	}()
	return func() {
		os.Stderr = prev
		log.SetOutput(prevLog)
		w.Close()
		<-done
		r.Close()
	}, nil
}

type scmHandler struct {
	name  string
	serve func(ctx context.Context, running func()) error
	// paramChange, when set, is called on SERVICE_CONTROL_PARAMCHANGE,
	// which the service then accepts.
	paramChange func()
	// preshutdown makes the service accept SERVICE_CONTROL_PRESHUTDOWN and
	// stop on it; install set its timeout (serviceDef.preshutdown).
	preshutdown bool
	log         *eventlog.Log
	err         error
}

// startWaitHint is the START_PENDING wait hint. serve reports running once
// its binary check passes, before it waits for run.lock, because a service
// in START_PENDING accepts no Stop.
const startWaitHint = 15 * time.Second

// stopWaitHint is the STOP_PENDING wait hint: the agent's stop budget.
const stopWaitHint = StopBudget

func (h *scmHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	pending := svc.Status{State: svc.StartPending, WaitHint: uint32(startWaitHint / time.Millisecond)}
	status <- pending
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	var once sync.Once
	running := func() { once.Do(func() { close(started) }) }
	done := make(chan error, 1)
	go func() { done <- h.serve(ctx, running) }()
	for {
		select {
		case <-started:
			started = nil
			accepts := svc.AcceptStop | svc.AcceptShutdown
			if h.paramChange != nil {
				accepts |= svc.AcceptParamChange
			}
			if h.preshutdown {
				accepts |= svc.AcceptPreShutdown
			}
			status <- svc.Status{State: svc.Running, Accepts: accepts}
		case h.err = <-done:
			// A non-zero service-specific code marks the exit a failure, so
			// the recovery actions restart the service.
			if h.err != nil {
				if h.log != nil {
					_ = h.log.Error(1, h.name+": "+h.err.Error())
				}
				return true, exitCode(h.err)
			}
			return false, 0
		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.ParamChange:
				if h.paramChange != nil {
					h.paramChange()
				}
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown, svc.PreShutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: uint32(stopWaitHint / time.Millisecond)}
				cancel()
				h.err = <-done
				return false, 0
			}
		}
	}
}

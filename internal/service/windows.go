//go:build windows

package service

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
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
		return fmt.Errorf("connect to the service control manager: %w", err)
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(WindowsName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return fn(m, nil)
	}
	if err != nil {
		return fmt.Errorf("open service %s: %w", WindowsName, err)
	}
	defer s.Close()
	return fn(m, s)
}

// ownedService refuses a service under WindowsName this package did not
// create, and returns its configuration.
func ownedService(s interface{ Config() (mgr.Config, error) }) (mgr.Config, error) {
	cfg, err := s.Config()
	if err != nil {
		return cfg, fmt.Errorf("read service %s: %w", WindowsName, err)
	}
	if !strings.Contains(cfg.Description, Marker) {
		return cfg, fmt.Errorf("%w: Windows service %q; remove it (sc.exe delete %s), then run the command again", ErrForeignUnit, WindowsName, WindowsName)
	}
	return cfg, nil
}

func (c scm) Check() ([]string, error) {
	return nil, c.open(func(_ *mgr.Mgr, s *mgr.Service) error {
		if s == nil {
			return nil
		}
		_, err := ownedService(s)
		return err
	})
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
	if _, err := ownedService(s); err != nil {
		return false, err
	}
	return true, checkNotMarkedForDelete(s)
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
func checkNotMarkedForDelete(s interface{ ChangeNothing() error }) error {
	if err := s.ChangeNothing(); err != nil {
		return markedForDelete(fmt.Errorf("read service %s: %w", WindowsName, err))
	}
	return nil
}

// markedForDelete maps ERROR_SERVICE_MARKED_FOR_DELETE to ErrMarkedForDelete
// with its remedy, and returns any other error unchanged.
func markedForDelete(err error) error {
	if errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return fmt.Errorf("%w: close the Services console, Event Viewer and any other tool showing the service, or restart Windows, then run the command again", ErrMarkedForDelete)
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
			return fmt.Errorf("query service %s: %w", WindowsName, err)
		}
		if status.State == svc.Running {
			pid = int(status.ProcessId)
		}
		return nil
	})
	return pid, err
}

// eventSourceKey is the registry key of the service's Event Log source.
const eventSourceKey = `SYSTEM\CurrentControlSet\Services\EventLog\Application\` + WindowsName

// registerEventSource registers WindowsName as an Event Log source unless it
// is registered already.
func registerEventSource() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, eventSourceKey, registry.QUERY_VALUE)
	if err == nil {
		k.Close()
		return nil
	}
	if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return fmt.Errorf("read event log source %s: %w", WindowsName, err)
	}
	if err := eventlog.InstallAsEventCreate(WindowsName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		return fmt.Errorf("register event log source %s: %w", WindowsName, err)
	}
	return nil
}

func removeEventSource() error {
	if err := eventlog.Remove(WindowsName); err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return fmt.Errorf("remove event log source %s: %w", WindowsName, err)
	}
	return nil
}

// winService is the part of a service control manager service the install,
// restart and stop paths use. scmService implements it; tests fake it.
type winService interface {
	Config() (mgr.Config, error)
	UpdateConfig(mgr.Config) error
	SetRequiredPrivileges(privileges []string) error
	SetRecoveryActions(actions []mgr.RecoveryAction, resetPeriod uint32) error
	SetRecoveryActionsOnNonCrashFailures(flag bool) error
	Query() (svc.Status, error)
	Control(c svc.Cmd) (svc.Status, error)
	Start(args ...string) error
}

// scmService adds the required privileges call x/sys lacks to *mgr.Service.
type scmService struct{ *mgr.Service }

func (s scmService) SetRequiredPrivileges(privileges []string) error {
	return setRequiredPrivileges(s.Handle, privileges)
}

func (c scm) Install(ctx context.Context, exe string) error {
	if err := registerEventSource(); err != nil {
		return err
	}
	return c.open(func(m *mgr.Mgr, s *mgr.Service) error {
		var existing winService
		if s != nil {
			existing = scmService{s}
		}
		return installService(ctx, exe, existing, func(want mgr.Config) (winService, func(), error) {
			created, err := m.CreateService(WindowsName, exe, want, "run", "--service")
			if err != nil {
				return nil, nil, err
			}
			return scmService{created}, func() { created.Close() }, nil
		})
	})
}

// installService creates the service through create when existing is nil,
// otherwise rewrites existing's configuration, then sets its required
// privileges and recovery actions and (re)starts it.
func installService(ctx context.Context, exe string, existing winService, create func(mgr.Config) (winService, func(), error)) error {
	want := mgr.Config{
		DisplayName:      "Localport device",
		Description:      windowsDescription,
		StartType:        mgr.StartAutomatic,
		ServiceStartName: windowsAccount,
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}
	s := existing
	if s == nil {
		created, closeCreated, err := create(want)
		if err != nil {
			return markedForDelete(fmt.Errorf("create service %s: %w", WindowsName, err))
		}
		defer closeCreated()
		s = created
	} else {
		cfg, err := ownedService(s)
		if err != nil {
			return err
		}
		cfg.BinaryPathName = syscall.EscapeArg(exe) + " run --service"
		cfg.DisplayName, cfg.Description = want.DisplayName, want.Description
		cfg.StartType, cfg.ServiceStartName, cfg.SidType = want.StartType, want.ServiceStartName, want.SidType
		if err := s.UpdateConfig(cfg); err != nil {
			return markedForDelete(fmt.Errorf("update service %s: %w", WindowsName, err))
		}
	}
	if err := s.SetRequiredPrivileges(serviceRequiredPrivileges); err != nil {
		return fmt.Errorf("set required privileges of service %s: %w", WindowsName, err)
	}
	// Restart on any exit, as systemd's Restart=always and launchd's
	// KeepAlive do; reset the failure count after a day.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second}}, 86400); err != nil {
		return fmt.Errorf("set recovery of service %s: %w", WindowsName, err)
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("set recovery of service %s: %w", WindowsName, err)
	}
	return restart(ctx, s)
}

func (c scm) Restart(ctx context.Context) error {
	return c.open(func(_ *mgr.Mgr, s *mgr.Service) error {
		if s == nil {
			return ErrNotInstalled
		}
		return restart(ctx, scmService{s})
	})
}

// Uninstall stops and deletes the service and removes its Event Log source,
// the source also when the service is already gone.
func (c scm) Uninstall(ctx context.Context) error {
	return c.open(func(_ *mgr.Mgr, s *mgr.Service) error {
		if s == nil {
			if err := removeEventSource(); err != nil {
				return err
			}
			return ErrNotInstalled
		}
		if _, err := ownedService(s); err != nil {
			return err
		}
		if err := stop(ctx, scmService{s}); err != nil {
			return err
		}
		if err := s.Delete(); err != nil {
			return fmt.Errorf("delete service %s: %w", WindowsName, err)
		}
		return removeEventSource()
	})
}

func restart(ctx context.Context, s winService) error {
	if err := stop(ctx, s); err != nil {
		return err
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("start service %s: %w", WindowsName, err)
	}
	return nil
}

// stop asks the service to stop and waits until it has. The service
// control manager has no completion event in x/sys, so its state is polled.
func stop(ctx context.Context, s winService) error {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("query service %s: %w", WindowsName, err)
	}
	if status.State == svc.Stopped {
		return nil
	}
	if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return fmt.Errorf("stop service %s: %w", WindowsName, err)
	}
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("stop service %s: %w", WindowsName, ctx.Err())
		case <-tick.C:
		}
		status, err := s.Query()
		if err != nil {
			return fmt.Errorf("query service %s: %w", WindowsName, err)
		}
		if status.State == svc.Stopped {
			return nil
		}
	}
}

// RunUnderSCM reports whether the service control manager started this
// process and, when it did, runs serve under the manager's control loop
// until the manager stops the service or serve returns. serve does all the
// work, config loading included, so a failure is reported to the manager as
// a service-specific exit code rather than a start timeout (an ExitError's
// Code, else 1). The service reports START_PENDING until serve calls running
// and then SERVICE_RUNNING accepting Stop and Shutdown, which cancel serve's
// context. Standard error and the log package's output go to the Event Log
// under the source WindowsName while serve runs.
func RunUnderSCM(serve func(ctx context.Context, running func()) error) (bool, error) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return false, fmt.Errorf("detect the service control manager: %w", err)
	}
	if !isService {
		return false, nil
	}
	h := &scmHandler{serve: serve}
	// Without the Event Log the service still runs; the manager records its
	// exit code.
	if elog, err := eventlog.Open(WindowsName); err == nil {
		defer elog.Close()
		h.log = elog
		if restore, err := stderrToEventLog(elog); err == nil {
			defer restore()
		}
	}
	if err := svc.Run(WindowsName, h); err != nil {
		return true, fmt.Errorf("run service %s: %w", WindowsName, err)
	}
	return true, h.err
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
	serve func(ctx context.Context, running func()) error
	log   *eventlog.Log
	err   error
}

// startWaitHint is the START_PENDING wait hint. serve reports running once
// its binary check passes, before it waits for run.lock, because a service
// in START_PENDING accepts no Stop.
const startWaitHint = 15 * time.Second

// stopWaitHint is the STOP_PENDING wait hint. It covers the session shutdown
// bound (10 s) and the tunnel stop that follows.
const stopWaitHint = 20 * time.Second

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
			status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
		case h.err = <-done:
			// A non-zero service-specific code marks the exit a failure, so
			// the recovery actions restart the service.
			if h.err != nil {
				if h.log != nil {
					_ = h.log.Error(1, "localport run: "+h.err.Error())
				}
				return true, exitCode(h.err)
			}
			return false, 0
		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: uint32(stopWaitHint / time.Millisecond)}
				cancel()
				h.err = <-done
				return false, 0
			}
		}
	}
}

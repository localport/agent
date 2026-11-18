//go:build windows

package service

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// The device service accepts SERVICE_CONTROL_PARAMCHANGE once running and
// hands each one to its reload; the launcher service, without one, does not
// accept it.
func TestExecuteDeliversParamChange(t *testing.T) {
	for _, withReload := range []bool{true, false} {
		reloads := make(chan struct{}, 1)
		h := &scmHandler{name: "test", serve: func(ctx context.Context, running func()) error {
			running()
			<-ctx.Done()
			return nil
		}}
		if withReload {
			h.paramChange = func() { reloads <- struct{}{} }
		}
		requests := make(chan svc.ChangeRequest, 2)
		status := make(chan svc.Status, 4)
		done := make(chan struct{})
		go func() { h.Execute(nil, requests, status); close(done) }()
		<-status
		running := <-status
		if got := running.Accepts&svc.AcceptParamChange != 0; got != withReload {
			t.Fatalf("reload %v: accepts ParamChange = %v", withReload, got)
		}
		if withReload {
			requests <- svc.ChangeRequest{Cmd: svc.ParamChange, CurrentStatus: running}
			select {
			case <-reloads:
			case <-time.After(5 * time.Second):
				t.Fatal("ParamChange did not reach the reload")
			}
			if got := <-status; got != running {
				t.Fatalf("status after ParamChange = %+v, want %+v", got, running)
			}
		}
		requests <- svc.ChangeRequest{Cmd: svc.Stop}
		<-done
	}
}

// After serve calls running, the service reports SERVICE_RUNNING accepting
// Stop, and a Stop cancels serve's context, which ends a wait in progress.
func TestExecuteAcceptsStopOnceRunningAndCancelsServe(t *testing.T) {
	waiting := make(chan struct{})
	h := &scmHandler{serve: func(ctx context.Context, running func()) error {
		running()
		close(waiting)
		<-ctx.Done() // stands in for the run.lock wait
		return ctx.Err()
	}}
	requests := make(chan svc.ChangeRequest, 1)
	status := make(chan svc.Status, 4)
	type result struct {
		specific bool
		code     uint32
	}
	done := make(chan result, 1)
	go func() {
		specific, code := h.Execute(nil, requests, status)
		done <- result{specific, code}
	}()
	if got := <-status; got.State != svc.StartPending || got.Accepts != 0 {
		t.Fatalf("first status = %+v, want START_PENDING accepting nothing", got)
	}
	<-waiting
	if got := <-status; got.State != svc.Running || got.Accepts&svc.AcceptStop == 0 {
		t.Fatalf("status after running = %+v, want SERVICE_RUNNING accepting Stop", got)
	}
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	select {
	case r := <-done:
		if r.specific || r.code != 0 {
			t.Fatalf("Execute after Stop = %v, %d, want a clean stop", r.specific, r.code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not end serve's wait")
	}
	if got := <-status; got.State != svc.StopPending || got.WaitHint != uint32(stopWaitHint/time.Millisecond) {
		t.Fatalf("status after Stop = %+v, want STOP_PENDING with a %v wait hint", got, stopWaitHint)
	}
}

// fakeService is a stopped service that records the install calls.
type fakeService struct {
	cfg                         mgr.Config
	updateErr, changeNothingErr error
	privileges                  []string
	preshutdown                 time.Duration
	updated                     bool
	calls                       []string
}

func (f *fakeService) Config() (mgr.Config, error) { return f.cfg, nil }
func (f *fakeService) UpdateConfig(c mgr.Config) error {
	f.updated, f.cfg = true, c
	return f.updateErr
}
func (f *fakeService) SetRequiredPrivileges(p []string) error {
	f.privileges = slices.Clone(p)
	f.calls = append(f.calls, "privileges")
	return nil
}
func (f *fakeService) SetPreshutdownTimeout(d time.Duration) error {
	f.preshutdown = d
	f.calls = append(f.calls, "preshutdown")
	return nil
}
func (f *fakeService) SetRecoveryActions([]mgr.RecoveryAction, uint32) error { return nil }
func (f *fakeService) SetRecoveryActionsOnNonCrashFailures(bool) error       { return nil }
func (f *fakeService) Query() (svc.Status, error)                            { return svc.Status{State: svc.Stopped}, nil }
func (f *fakeService) Control(svc.Cmd) (svc.Status, error)                   { return svc.Status{}, nil }
func (f *fakeService) Start(...string) error {
	f.calls = append(f.calls, "start")
	return nil
}
func (f *fakeService) ChangeNothing() error { return f.changeNothingErr }

// Install sets the device service's preshutdown timeout to the stop budget on
// create and on update, before it starts the service; the launcher gets none,
// so it is still running while the agent ends its sessions.
func TestInstallSetsThePreshutdownTimeout(t *testing.T) {
	for name, d := range map[string]serviceDef{"agent": agentDef(`C:\l.exe`), "launcher": launcherDef(`C:\l.exe`)} {
		for _, existing := range []*fakeService{nil, {cfg: mgr.Config{Description: d.description}}} {
			created := &fakeService{}
			create := func(mgr.Config) (winService, func(), error) { return created, func() {}, nil }
			var current winService
			got := created
			if existing != nil {
				current, got = existing, existing
			}
			if err := installDefinition(context.Background(), d, current, create); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			want, wantCalls := time.Duration(0), []string{"privileges", "start"}
			if name == "agent" {
				want, wantCalls = StopBudget, []string{"privileges", "preshutdown", "start"}
			}
			if got.preshutdown != want || !slices.Equal(got.calls, wantCalls) {
				t.Fatalf("%s (existing %v): preshutdown %v, calls %q; want %v, %q", name, existing != nil, got.preshutdown, got.calls, want, wantCalls)
			}
		}
	}
}

// The preshutdown timeout reaches ChangeServiceConfig2 as a
// SERVICE_PRESHUTDOWN_INFO in milliseconds.
func TestSetPreshutdownTimeoutPassesMilliseconds(t *testing.T) {
	prev := changeServiceConfig2
	t.Cleanup(func() { changeServiceConfig2 = prev })
	var level, got uint32
	changeServiceConfig2 = func(_ windows.Handle, infoLevel uint32, info *byte) error {
		level, got = infoLevel, (*servicePreshutdownInfo)(unsafe.Pointer(info)).preshutdownTimeout
		return nil
	}
	if err := setPreshutdownTimeout(0, StopBudget); err != nil {
		t.Fatal(err)
	}
	if level != windows.SERVICE_CONFIG_PRESHUTDOWN_INFO || got != uint32(StopBudget/time.Millisecond) {
		t.Fatalf("ChangeServiceConfig2(level %d, %d ms), want level %d with %d ms", level, got, windows.SERVICE_CONFIG_PRESHUTDOWN_INFO, StopBudget/time.Millisecond)
	}
}

// A handler with preshutdown accepts SERVICE_CONTROL_PRESHUTDOWN and stops on
// it with the stop budget as its wait hint; one without does not accept it.
func TestExecutePreShutdownStops(t *testing.T) {
	for _, preshutdown := range []bool{true, false} {
		h := &scmHandler{preshutdown: preshutdown, serve: func(ctx context.Context, running func()) error {
			running()
			<-ctx.Done()
			return nil
		}}
		requests := make(chan svc.ChangeRequest, 1)
		status := make(chan svc.Status, 4)
		done := make(chan struct{})
		go func() { h.Execute(nil, requests, status); close(done) }()
		<-status
		running := <-status
		if got := running.Accepts&svc.AcceptPreShutdown != 0; got != preshutdown {
			t.Fatalf("preshutdown %v: accepts PreShutdown = %v", preshutdown, got)
		}
		if !preshutdown {
			requests <- svc.ChangeRequest{Cmd: svc.Stop}
			<-done
			continue
		}
		requests <- svc.ChangeRequest{Cmd: svc.PreShutdown}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("PreShutdown did not stop the service")
		}
		if got := <-status; got.State != svc.StopPending || got.WaitHint != uint32(StopBudget/time.Millisecond) {
			t.Fatalf("status after PreShutdown = %+v, want STOP_PENDING with a %v wait hint", got, StopBudget)
		}
	}
}

// Install restricts the service's privileges to SeChangeNotifyPrivilege on
// create and on update, before it starts the service.
func TestInstallSetsTheRequiredPrivileges(t *testing.T) {
	created := &fakeService{}
	create := func(mgr.Config) (winService, func(), error) { return created, func() {}, nil }
	existing := &fakeService{cfg: mgr.Config{Description: windowsDescription}}
	for name, tc := range map[string]struct {
		existing winService
		got      *fakeService
	}{"create": {nil, created}, "update": {existing, existing}} {
		if err := installService(context.Background(), `C:\Program Files\Localport\localport.exe`, tc.existing, create); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !slices.Equal(tc.got.privileges, []string{"SeChangeNotifyPrivilege"}) || !slices.Equal(tc.got.calls, []string{"privileges", "preshutdown", "start"}) {
			t.Fatalf("%s: privileges %q, calls %q; want [SeChangeNotifyPrivilege] set before start", name, tc.got.privileges, tc.got.calls)
		}
	}
}

// A service marked for deletion refuses create, update and the installed
// check with ErrMarkedForDelete; another error stays itself.
func TestMarkedForDeleteIsReported(t *testing.T) {
	marked := windows.ERROR_SERVICE_MARKED_FOR_DELETE
	create := func(mgr.Config) (winService, func(), error) { return nil, nil, marked }
	if err := installService(context.Background(), `C:\l.exe`, nil, create); !errors.Is(err, ErrMarkedForDelete) {
		t.Fatalf("create = %v, want ErrMarkedForDelete", err)
	}
	existing := &fakeService{cfg: mgr.Config{Description: windowsDescription}, updateErr: marked}
	if err := installService(context.Background(), `C:\l.exe`, existing, nil); !errors.Is(err, ErrMarkedForDelete) {
		t.Fatalf("update = %v, want ErrMarkedForDelete", err)
	}
	owned := mgr.Config{Description: windowsDescription}
	if installed, err := installedState(&fakeService{cfg: owned, changeNothingErr: marked}); !installed || !errors.Is(err, ErrMarkedForDelete) {
		t.Fatalf("installed state = %v, %v, want true with ErrMarkedForDelete", installed, err)
	}
	if installed, err := installedState(&fakeService{cfg: owned}); !installed || err != nil {
		t.Fatalf("installed state of a live service = %v, %v, want true", installed, err)
	}
	if _, err := installedState(&fakeService{cfg: owned, changeNothingErr: windows.ERROR_ACCESS_DENIED}); err == nil || errors.Is(err, ErrMarkedForDelete) {
		t.Fatalf("installed state on access denied = %v, want that error", err)
	}
	if installed, err := installedState(&fakeService{}); installed || !errors.Is(err, ErrForeignUnit) {
		t.Fatalf("installed state of a foreign service = %v, %v, want ErrForeignUnit", installed, err)
	}
}

// The required privileges list reaches ChangeServiceConfig2 as a
// SERVICE_REQUIRED_PRIVILEGES_INFO holding SeChangeNotifyPrivilege only.
func TestSetRequiredPrivilegesPassesTheList(t *testing.T) {
	prev := changeServiceConfig2
	t.Cleanup(func() { changeServiceConfig2 = prev })
	var level uint32
	var got []string
	changeServiceConfig2 = func(_ windows.Handle, infoLevel uint32, info *byte) error {
		level = infoLevel
		p := (*serviceRequiredPrivilegesInfo)(unsafe.Pointer(info)).requiredPrivileges
		for *p != 0 {
			s := windows.UTF16PtrToString(p)
			got = append(got, s)
			p = (*uint16)(unsafe.Add(unsafe.Pointer(p), 2*(len(utf16.Encode([]rune(s)))+1)))
		}
		return nil
	}
	if err := setRequiredPrivileges(0, serviceRequiredPrivileges); err != nil {
		t.Fatal(err)
	}
	if level != windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO || !slices.Equal(got, []string{"SeChangeNotifyPrivilege"}) {
		t.Fatalf("ChangeServiceConfig2(level %d, %q), want level %d with [SeChangeNotifyPrivilege]", level, got, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO)
	}
}

// An ExitError's Code becomes the service-specific exit code.
func TestExecuteReportsExitErrorCode(t *testing.T) {
	const want = 3
	h := &scmHandler{serve: func(context.Context, func()) error {
		return &ExitError{Code: want, Err: errors.New("the run failed")}
	}}
	status := make(chan svc.Status, 4)
	if specific, code := h.Execute(nil, make(chan svc.ChangeRequest), status); !specific || code != want {
		t.Fatalf("Execute = %v, %d, want a service-specific exit %d", specific, code, want)
	}
}

// restartingService reports the states in order, then Stopped, and counts
// each Stop control.
type restartingService struct {
	fakeService
	states []svc.State
	stops  int
}

func (r *restartingService) Query() (svc.Status, error) {
	if len(r.states) == 0 {
		return svc.Status{State: svc.Stopped}, nil
	}
	state := r.states[0]
	r.states = r.states[1:]
	return svc.Status{State: state}, nil
}

func (r *restartingService) Control(svc.Cmd) (svc.Status, error) {
	r.stops++
	return svc.Status{}, nil
}

// A recovery restart during the stop wait is stopped again, not waited out.
func TestStopStopsARecoveryRestartAgain(t *testing.T) {
	s := &restartingService{states: []svc.State{svc.Running, svc.StopPending, svc.Running, svc.StopPending}}
	if err := stop(context.Background(), LauncherName, s); err != nil {
		t.Fatal(err)
	}
	if s.stops != 2 {
		t.Fatalf("Stop sent %d times, want 2 (the first and once after the restart)", s.stops)
	}
}

// A command line names a program inside the directory whether quoted or not,
// with spaces in its path, environment references or a native \??\ prefix;
// a program elsewhere, or one whose path only shares a prefix, is outside.
func TestImageInside(t *testing.T) {
	t.Setenv("LOCALPORT_TEST_ROOT", `C:\Program Files`)
	dir := `C:\Program Files\Localport`
	for cmd, inside := range map[string]bool{
		`"C:\Program Files\Localport\other.exe" run`:                        true,
		`C:\Program Files\Localport\other.exe run`:                          true,
		`c:\program files\localport\other.exe`:                              true,
		`%LOCALPORT_TEST_ROOT%\Localport\other.exe`:                         true,
		`\??\C:\Program Files\Localport\driver.sys`:                         true,
		`"C:\Program Files\LocalportTools\x.exe"`:                           false,
		`"C:\Windows\system32\svchost.exe" -k "C:\Program Files\Localport"`: false,
		`C:\Program Files\Localport`:                                        false,
	} {
		if got := imageInside(cmd, dir); got != inside {
			t.Errorf("imageInside(%q) = %v, want %v", cmd, got, inside)
		}
	}
}

// programOf reads the program of the command lines Install writes.
func TestProgramOf(t *testing.T) {
	for cmd, want := range map[string]string{
		`"C:\Program Files\Localport\localport.exe" run --service`: `C:\Program Files\Localport\localport.exe`,
		`C:\Localport\localport.exe run --service`:                 `C:\Localport\localport.exe`,
		`  "C:\x\y.exe"`: `C:\x\y.exe`,
	} {
		if got := programOf(cmd); got != want {
			t.Errorf("programOf(%q) = %q, want %q", cmd, got, want)
		}
	}
}

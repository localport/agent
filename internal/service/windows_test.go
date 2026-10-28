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
func (f *fakeService) SetRecoveryActions([]mgr.RecoveryAction, uint32) error { return nil }
func (f *fakeService) SetRecoveryActionsOnNonCrashFailures(bool) error       { return nil }
func (f *fakeService) Query() (svc.Status, error)                            { return svc.Status{State: svc.Stopped}, nil }
func (f *fakeService) Control(svc.Cmd) (svc.Status, error)                   { return svc.Status{}, nil }
func (f *fakeService) Start(...string) error {
	f.calls = append(f.calls, "start")
	return nil
}
func (f *fakeService) ChangeNothing() error { return f.changeNothingErr }

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
		if !slices.Equal(tc.got.privileges, []string{"SeChangeNotifyPrivilege"}) || !slices.Equal(tc.got.calls, []string{"privileges", "start"}) {
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
	h := &scmHandler{serve: func(context.Context, func()) error {
		return &ExitError{Code: ExitRunLocked, Err: errors.New("run.lock is held")}
	}}
	status := make(chan svc.Status, 4)
	if specific, code := h.Execute(nil, make(chan svc.ChangeRequest), status); !specific || code != ExitRunLocked {
		t.Fatalf("Execute = %v, %d, want a service-specific exit %d", specific, code, ExitRunLocked)
	}
}

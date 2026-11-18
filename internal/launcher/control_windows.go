//go:build windows

package launcher

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// ControlPipePath is a foreground run's control endpoint. Only SYSTEM and
// Administrators can create a pipe under ProtectedPrefix\Administrators, so no
// other account can hold the name first.
const ControlPipePath = `\\.\pipe\ProtectedPrefix\Administrators\Localport\control`

// controlPipeSDDL owns the pipe by Administrators and grants only SYSTEM and
// Administrators; an unelevated administrator's filtered token is denied.
const controlPipeSDDL = "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)"

// ControlListener is a bound control endpoint.
type ControlListener struct {
	pl *PipeListener
}

// ListenControl creates the control pipe. The first instance fails when the
// name exists, returned as ErrControlBusy: another process serves it.
func ListenControl() (*ControlListener, error) {
	stop, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	pl := &PipeListener{name: ControlPipePath, sddl: controlPipeSDDL, first: true, stop: stop}
	if err := pl.prepare(); err != nil {
		_ = windows.CloseHandle(stop)
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return nil, ErrControlBusy
		}
		return nil, err
	}
	return &ControlListener{pl: pl}, nil
}

// Serve answers control requests until ctx ends or the listener is closed,
// calling reload for each one (answerControl). The pipe's DACL admits only
// SYSTEM and elevated Administrators. Requests are served one at a time, each
// bounded by controlTimeout.
func (l *ControlListener) Serve(ctx context.Context, reload func() bool, logf func(format string, args ...any)) {
	stop := context.AfterFunc(ctx, func() { _ = l.pl.Close() })
	defer stop()
	var delay time.Duration
	for {
		conn, err := l.pl.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			logf("control endpoint: accept: %v; retrying in %v", err, delay)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return
			}
			continue
		}
		delay = 0
		if err := answerControl(conn, reload); err != nil {
			logf("control endpoint: %v", err)
		}
		_ = conn.Close()
	}
}

// Close stops Serve and releases the pipe.
func (l *ControlListener) Close() error { return l.pl.Close() }

// RequestReload asks the foreground run serving the control pipe to reload
// its config, after checking the pipe's owner and DACL (checkAdminPipe). It
// returns ErrRunStarting while the run has not yet read the config, and
// ErrNoForegroundRun when no run serves it.
func RequestReload(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	conn, err := openControlPipe(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	// The run creates the pipe right after it takes run.lock and answers while
	// it starts, so no wait covers a start.
	return askReload(conn, controlTimeout)
}

// openControlPipe opens the control pipe at identification level, retrying
// while every instance is busy, and checks it.
func openControlPipe(ctx context.Context) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(ControlPipePath)
	if err != nil {
		return nil, err
	}
	var h windows.Handle
	for {
		h, err = windows.CreateFile(p, pipeClientRights, 0, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			break
		}
		switch {
		case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
			return nil, ErrNoForegroundRun
		case !errors.Is(err, windows.ERROR_PIPE_BUSY):
			return nil, &fs.PathError{Op: "open", Path: ControlPipePath, Err: err}
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("open %s: %w", ControlPipePath, ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err == nil {
		err = checkAdminPipe(sd, ErrControlUntrusted)
	}
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	return os.NewFile(uintptr(h), ControlPipePath), nil
}

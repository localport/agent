//go:build windows

package launcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// OpenStatus opens the device service's status publication: a KindStatus
// request the launcher accepts with Publishing. The caller writes frames
// with WriteStatusFrame and closes the connection to withdraw its document.
// A second publisher is refused with CodeBusy.
func (c Client) OpenStatus(ctx context.Context) (io.ReadWriteCloser, error) {
	ctx, cancel := context.WithTimeout(ctx, StartTimeout)
	defer cancel()
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	if err := writeMessage(conn, Request{V: Version, Kind: KindStatus}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	resp, err := readResponse(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	switch {
	case resp.Publishing:
		_ = conn.SetDeadline(time.Time{})
		return conn, nil
	case resp.Refused != nil:
		conn.Close()
		return nil, clientRefusal(resp.Refused.Code, nil)
	}
	conn.Close()
	return nil, errors.New("launcher: unexpected response to a status request")
}

// statusReadTimeout bounds a status read.
const statusReadTimeout = 3 * time.Second

// ErrStatusUntrusted refuses a status pipe that is not the launcher's: its
// owner is not SYSTEM or Administrators, or its DACL admits anyone else.
var ErrStatusUntrusted = errors.New("the status pipe is not the launcher's")

// ErrStatusDenied is the status pipe refusing this token: only SYSTEM and an
// elevated Administrator may read it.
var ErrStatusDenied = errors.New("the status pipe admits only an elevated Administrator")

// ReadStatus reads the status document from the launcher's status pipe after
// checking its owner and DACL: at most MaxStatusFrame bytes within
// statusReadTimeout. Empty means the device service publishes none.
func ReadStatus(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, statusReadTimeout)
	defer cancel()
	conn, err := openStatusPipe(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	raw, err := io.ReadAll(io.LimitReader(conn, MaxStatusFrame+1))
	if err != nil && !errors.Is(err, windows.ERROR_BROKEN_PIPE) {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if len(raw) > MaxStatusFrame {
		return nil, fmt.Errorf("%w: over %d bytes", ErrStatusFrame, MaxStatusFrame)
	}
	return raw, nil
}

// openStatusPipe opens the status pipe for reading at identification level,
// retrying while every instance is busy, and checks it (checkStatusPipe).
func openStatusPipe(ctx context.Context) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(StatusPipePath)
	if err != nil {
		return nil, err
	}
	var h windows.Handle
	for {
		h, err = windows.CreateFile(p, statusReadAccess, 0, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			break
		}
		switch {
		case errors.Is(err, windows.ERROR_ACCESS_DENIED):
			return nil, ErrStatusDenied
		case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
			return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
		case !errors.Is(err, windows.ERROR_PIPE_BUSY):
			return nil, &fs.PathError{Op: "open", Path: StatusPipePath, Err: err}
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: open %s: %w", ErrUnavailable, StatusPipePath, ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err == nil {
		err = checkStatusPipe(sd)
	}
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	return os.NewFile(uintptr(h), StatusPipePath), nil
}

// checkStatusPipe is checkAdminPipe for the status pipe.
func checkStatusPipe(sd *windows.SECURITY_DESCRIPTOR) error {
	return checkAdminPipe(sd, ErrStatusUntrusted)
}

// checkAdminPipe refuses, with untrusted, unless the owner is SYSTEM or
// Administrators and every allow entry of the DACL names SYSTEM or
// Administrators. The owner alone is not enough: an Administrators-owned pipe
// may still grant others.
func checkAdminPipe(sd *windows.SECURITY_DESCRIPTOR, untrusted error) error {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	trusted := func(sid *windows.SID) bool { return sid.Equals(system) || sid.Equals(admins) }
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read the pipe owner: %w", err)
	}
	if !trusted(owner) {
		return fmt.Errorf("%w: owned by %s", untrusted, owner)
	}
	dacl, _, err := sd.DACL()
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return fmt.Errorf("%w: no DACL admits everyone", untrusted)
	}
	if err != nil {
		return fmt.Errorf("read the pipe DACL: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("%w: no DACL admits everyone", untrusted)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("read the pipe DACL: %w", err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
				continue
			}
			return fmt.Errorf("%w: entry type %d", untrusted, ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !trusted(sid) {
			return fmt.Errorf("%w: grants %s", untrusted, sid)
		}
	}
	return nil
}

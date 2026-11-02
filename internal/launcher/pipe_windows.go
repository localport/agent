//go:build windows

package launcher

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PipePath is the launcher's named pipe.
const PipePath = `\\.\pipe\localport-session`

// pipeClientAccess is what a pipe's DACL grants its one client: read and
// write data, read attributes and the security descriptor. It leaves out
// FILE_APPEND_DATA, which on a pipe is FILE_CREATE_PIPE_INSTANCE, so the
// client can never serve an instance of the name itself.
const pipeClientAccess = "0x12008b"

// pipeClientRights is pipeClientAccess as the rights a client requests:
// FILE_GENERIC_READ and FILE_WRITE_DATA. GENERIC_WRITE would ask for more
// than the DACL grants and be denied.
const pipeClientRights = 0x12008b

const pipeBufferSize = 64 << 10

var procImpersonateNamedPipeClient = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

// createPipeInstance creates one overlapped byte-mode instance of name under
// sddl that refuses remote clients. first fails when the name already
// exists, so nobody can hold the name before the creator.
func createPipeInstance(name, sddl string, first bool, maxInstances uint32) (windows.Handle, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return 0, fmt.Errorf("pipe security descriptor: %w", err)
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	mode := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		mode |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	h, err := windows.CreateNamedPipe(p, mode,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		maxInstances, pipeBufferSize, pipeBufferSize, 0, sa)
	if err != nil {
		return 0, fmt.Errorf("create pipe %s: %w", name, err)
	}
	return h, nil
}

// PipeListener accepts clients on the launcher pipe. Accept runs on one
// goroutine; Close may run on any.
type PipeListener struct {
	name, sddl string
	first      bool
	stop       windows.Handle
	// next is the instance waiting for the next client. Accept creates it
	// before returning a connection, so the name does not lapse between
	// clients unless that creation fails. A process that takes a lapsed
	// name only denies service: the agent refuses a pipe not owned by
	// SYSTEM.
	next windows.Handle
}

// ListenPipe creates the launcher pipe owned by SYSTEM, granting SYSTEM full
// access and agent pipeClientAccess. The first instance fails when the name
// exists, so a process that took the name first is never served.
func ListenPipe(agent *windows.SID) (*PipeListener, error) {
	stop, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	l := &PipeListener{
		name:  PipePath,
		sddl:  fmt.Sprintf("O:SYD:P(A;;GA;;;SY)(A;;%s;;;%s)", pipeClientAccess, agent),
		first: true,
		stop:  stop,
	}
	// The first instance now: a name already taken fails the start.
	if err := l.prepare(); err != nil {
		_ = windows.CloseHandle(stop)
		return nil, err
	}
	return l, nil
}

// prepare creates the waiting instance when there is none.
func (l *PipeListener) prepare() error {
	if l.next != 0 {
		return nil
	}
	h, err := createPipeInstance(l.name, l.sddl, l.first, windows.PIPE_UNLIMITED_INSTANCES)
	if err != nil {
		return err
	}
	l.first, l.next = false, h
	return nil
}

// Accept waits for the next client and returns its connection, pollable so
// deadlines apply. It returns net.ErrClosed after Close.
func (l *PipeListener) Accept() (*os.File, error) {
	if ev, _ := windows.WaitForSingleObject(l.stop, 0); ev == windows.WAIT_OBJECT_0 {
		return nil, net.ErrClosed
	}
	if err := l.prepare(); err != nil {
		return nil, err
	}
	h := l.next
	if err := connectPipe(h, l.stop); err != nil {
		_ = windows.CloseHandle(h)
		l.next = 0
		return nil, err
	}
	// The next instance exists before this one is handed out; when that
	// fails the next Accept tries again.
	l.next = 0
	_ = l.prepare()
	// The handle joins the runtime poller only now, so the completion of the
	// connect above never reaches it.
	return os.NewFile(uintptr(h), l.name), nil
}

// connectPipe waits for a client on h, or for stop.
func connectPipe(h, stop windows.Handle) error {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(ev) }()
	ov := windows.Overlapped{HEvent: ev}
	err = windows.ConnectNamedPipe(h, &ov)
	switch {
	case err == nil, errors.Is(err, windows.ERROR_PIPE_CONNECTED):
		return nil
	case !errors.Is(err, windows.ERROR_IO_PENDING):
		return fmt.Errorf("connect pipe: %w", err)
	}
	r, err := windows.WaitForMultipleObjects([]windows.Handle{ev, stop}, false, windows.INFINITE)
	if err != nil {
		return err
	}
	var n uint32
	if r == windows.WAIT_OBJECT_0+1 {
		_ = windows.CancelIoEx(h, &ov)
		_ = windows.GetOverlappedResult(h, &ov, &n, true)
		return net.ErrClosed
	}
	if err := windows.GetOverlappedResult(h, &ov, &n, false); err != nil {
		return fmt.Errorf("connect pipe: %w", err)
	}
	return nil
}

// Close stops Accept; connections already returned stay open.
func (l *PipeListener) Close() error { return windows.SetEvent(l.stop) }

// pipeClientSID returns the user SID of the client connected to conn,
// read by impersonating it at the level it allowed (identification).
func pipeClientSID(conn *os.File) (*windows.SID, error) {
	runtime.LockOSThread()
	if r, _, e := procImpersonateNamedPipeClient.Call(conn.Fd()); r == 0 {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("impersonate the pipe client: %w", e)
	}
	var tok windows.Token
	openErr := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &tok)
	if err := windows.RevertToSelf(); err != nil {
		// The thread still carries the client's identity: leave it locked,
		// so it ends with this goroutine instead of serving another.
		if openErr == nil {
			_ = tok.Close()
		}
		return nil, fmt.Errorf("revert the pipe client impersonation: %w", err)
	}
	runtime.UnlockOSThread()
	if openErr != nil {
		return nil, fmt.Errorf("read the pipe client token: %w", openErr)
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read the pipe client token: %w", err)
	}
	return u.User.Sid.Copy()
}

// pipeOwner returns the owner SID of the pipe h is connected to. The owner
// is fixed by the creator of the first instance: only SYSTEM (or a holder of
// SeRestorePrivilege) can name SYSTEM.
func pipeOwner(h windows.Handle) (*windows.SID, error) {
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("read the pipe owner: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return nil, fmt.Errorf("read the pipe owner: %w", err)
	}
	return owner.Copy()
}

// errPipeOwner is a pipe whose owner is not the expected server.
var errPipeOwner = errors.New("the pipe is not owned by the expected server")

// dialPipe opens name as a client at identification level, retrying while
// every instance is busy until ctx ends, and refuses a pipe not owned by
// owner. The returned file is pollable.
func dialPipe(ctx context.Context, name string, owner *windows.SID) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(name)
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
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return nil, fmt.Errorf("open %s: %w", name, err)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("open %s: %w", name, ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	got, err := pipeOwner(h)
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	if !got.Equals(owner) {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("%w: %s is owned by %s, want %s", errPipeOwner, name, got, owner)
	}
	return os.NewFile(uintptr(h), name), nil
}

// NewSessionChannel creates the agent's end of a session channel: a
// one-instance pipe under a random SessionPipePrefix name, owned by this
// process's user, which only that user and SYSTEM (the helper) may open.
// The helper connects before the launcher reports the session started.
func NewSessionChannel() (ours *os.File, pipe string, err error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, "", fmt.Errorf("read process token: %w", err)
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, "", err
	}
	name := SessionPipePrefix + hex.EncodeToString(b[:])
	me := user.User.Sid.String()
	h, err := createPipeInstance(name, fmt.Sprintf("O:%sD:P(A;;GA;;;%s)(A;;%s;;;SY)", me, me, pipeClientAccess), true, 1)
	if err != nil {
		return nil, "", err
	}
	return os.NewFile(uintptr(h), name), name, nil
}

// OpenSessionChannel opens the session channel pipe as the helper and
// refuses one not owned by agent.
func OpenSessionChannel(ctx context.Context, pipe string, agent *windows.SID) (*os.File, error) {
	if !pipePattern.MatchString(pipe) {
		return nil, errors.New("launcher: bad session pipe name")
	}
	return dialPipe(ctx, pipe, agent)
}

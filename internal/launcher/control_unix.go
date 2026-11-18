//go:build linux || darwin

package launcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// controlSocket is ControlSocketPath; tests point it at their own socket.
var controlSocket = ControlSocketPath

// controlOwner is the uid that owns the control endpoint and the only peer
// it serves: root. Tests set their own uid.
var controlOwner = func() uint32 { return 0 }

// controlAnswerWait bounds the client's side of one exchange, which also
// covers a run still starting before it accepts.
const controlAnswerWait = 10 * time.Second

// errNotControlSocket refuses a descriptor root passed that is not the
// control socket: a fault in the relay, not a file on disk.
var errNotControlSocket = errors.New("the passed descriptor is not the control socket")

// ControlSocket is the listening control endpoint as the holder of run.lock
// opened it (OpenControl), the half of socket activation that root keeps: it
// answers that the run is starting while it enrols (ServeStarting), then
// passes File to the process that serves the devices (ControlListenerOn). A
// connect between the two waits in the backlog; once every descriptor is
// closed the waiting clients are reset.
type ControlSocket struct {
	file *os.File
	path string
}

// OpenControl binds and listens on the control endpoint: mode 0600, owned by
// root, in a root-owned directory neither group nor others can write, which
// it creates with mode 0755 (as the systemd socket units do) when missing.
// The caller holds run.lock, which makes it the only owner of the socket's
// path: a socket already there is one a run that exited left, and is
// replaced.
func OpenControl() (*ControlSocket, error) {
	path := controlSocket
	dir := filepath.Dir(path)
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	if err := checkControlDir(dir); err != nil {
		return nil, err
	}
	file, err := bindControl(path)
	if err != nil {
		return nil, err
	}
	if err := unix.Listen(int(file.Fd()), unix.SOMAXCONN); err != nil {
		return nil, errors.Join(fmt.Errorf("listen on %s: %w", path, err), file.Close(), os.Remove(path))
	}
	return &ControlSocket{file: file, path: path}, nil
}

// File is the listening socket, for the process that accepts on it.
func (c *ControlSocket) File() *os.File { return c.file }

// Close closes this process's copy of the socket and removes its path. The
// caller still holds run.lock, so the path it removes is its own.
func (c *ControlSocket) Close() error {
	err := c.file.Close()
	if errors.Is(err, os.ErrClosed) {
		err = nil
	}
	if rmErr := os.Remove(c.path); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
		err = errors.Join(err, rmErr)
	}
	return err
}

// bindControl removes a socket a run that exited left (the caller holds
// run.lock, so none is live) and binds a new stream socket at path with mode
// 0600.
func bindControl(path string) (*os.File, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("%w: %s exists and is not a socket", ErrControlUntrusted, path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	// Close-on-exec is set under ForkLock, as the net package does where
	// SOCK_CLOEXEC is missing (macOS), so no concurrent exec inherits it.
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("control socket: %w", err)
	}
	old := unix.Umask(0o177)
	err = unix.Bind(fd, &unix.SockaddrUnix{Name: path})
	unix.Umask(old)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bind %s: %w", path, err)
	}
	return os.NewFile(uintptr(fd), path), nil
}

// ControlListener is a listening control endpoint.
type ControlListener struct {
	ln *net.UnixListener
	// sock is the socket ListenControl opened in this process, closed with
	// the listener; nil for a socket root passed (root removes it).
	sock *ControlSocket
	// peer is the only uid served, controlOwner at listen time.
	peer uint32
}

// ListenControl opens the control endpoint (OpenControl) for a process that
// holds run.lock and serves the devices itself.
func ListenControl() (*ControlListener, error) {
	sock, err := OpenControl()
	if err != nil {
		return nil, err
	}
	l, err := ControlListenerOn(sock.File())
	if err != nil {
		return nil, errors.Join(err, sock.Close())
	}
	l.sock = sock
	return l, nil
}

// ControlListenerOn serves f, the socket OpenControl opened, after checking
// that it is a Unix stream socket bound at the control endpoint's path. The
// caller serves the devices under run.lock. f is closed; the listener holds
// its own descriptor.
func ControlListenerOn(f *os.File) (*ControlListener, error) {
	defer f.Close()
	fd := int(f.Fd())
	typ, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		return nil, fmt.Errorf("control socket: %w", err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return nil, fmt.Errorf("control socket: %w", err)
	}
	if ua, ok := sa.(*unix.SockaddrUnix); typ != unix.SOCK_STREAM || !ok || ua.Name != controlSocket {
		return nil, errNotControlSocket
	}
	// OpenControl listened already; macOS cannot report that (SO_ACCEPTCONN),
	// and listening again on a listening socket changes nothing.
	if err := unix.Listen(fd, unix.SOMAXCONN); err != nil {
		return nil, fmt.Errorf("listen on %s: %w", controlSocket, err)
	}
	ln, err := net.FileListener(f)
	if err != nil {
		return nil, err
	}
	return &ControlListener{ln: ln.(*net.UnixListener), peer: controlOwner()}, nil
}

// ServeStarting answers controlStarting on the socket until stop, for the
// holder of run.lock while it enrols, before it passes the socket to the
// process that serves the devices. It serves a duplicate descriptor, so stop
// leaves the socket listening: a client that connects after stop waits in the
// backlog for that process. stop returns once no request is being answered.
func (c *ControlSocket) ServeStarting(logf func(format string, args ...any)) (stop func(), err error) {
	ln, err := net.FileListener(c.file)
	if err != nil {
		return nil, fmt.Errorf("control socket: %w", err)
	}
	l := &ControlListener{ln: ln.(*net.UnixListener), peer: controlOwner()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.Serve(ctx, func() bool { return false }, logf)
	}()
	return func() {
		cancel()
		<-done
	}, nil
}

// Serve answers control requests until ctx ends or the listener is closed,
// calling reload for each one (answerControl). Only the owner (root) is
// served; any other peer is closed without a byte. Requests are served one at
// a time, each bounded by controlTimeout.
func (l *ControlListener) Serve(ctx context.Context, reload func() bool, logf func(format string, args ...any)) {
	stop := context.AfterFunc(ctx, func() { _ = l.ln.Close() })
	defer stop()
	var delay time.Duration
	for {
		conn, err := l.ln.AcceptUnix()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			// EMFILE and the like are retried with a backoff, as ServeStatus does.
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
		l.serveConn(conn, reload, logf)
	}
}

func (l *ControlListener) serveConn(conn *net.UnixConn, reload func() bool, logf func(format string, args ...any)) {
	defer conn.Close()
	uid, pid, err := peerCred(conn)
	if err != nil {
		logf("control endpoint: peer credentials: %v", err)
		return
	}
	if uid != l.peer {
		logf("control endpoint: refused uid %d (pid %d): not root", uid, pid)
		return
	}
	if err := answerControl(conn, reload); err != nil {
		logf("control endpoint: %v", err)
	}
}

// Close stops listening and, for an endpoint ListenControl opened, removes
// the socket.
func (l *ControlListener) Close() error {
	err := l.ln.Close()
	if errors.Is(err, net.ErrClosed) {
		// Serve's context closed it first.
		err = nil
	}
	if l.sock != nil {
		err = errors.Join(err, l.sock.Close())
	}
	return err
}

// RequestReload asks the foreground run serving the control endpoint to
// reload its config, after checking that root owns the endpoint
// (checkControlSocket). It returns ErrRunStarting while the run has not yet
// read the config; a connect during root's hand-off to the child waits until
// the child accepts. It returns ErrNoForegroundRun when no run serves the endpoint: the
// socket is missing, a run that exited left it (the connect is refused), or
// the run exited before it answered (the connection is reset or closed).
func RequestReload(ctx context.Context) error {
	path := controlSocket
	if err := checkControlSocket(path); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, controlAnswerWait)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if errors.Is(err, syscall.ECONNREFUSED) {
		return ErrNoForegroundRun
	}
	if err != nil {
		return err
	}
	defer c.Close()
	return reloadOn(c.(*net.UnixConn))
}

// reloadOn asks for a reload on c, a connection to the control endpoint. A
// connection reset or closed before the answer means the run exited before it
// accepted or answered: ErrNoForegroundRun.
func reloadOn(c *net.UnixConn) error {
	err := askReload(c, controlAnswerWait)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return ErrNoForegroundRun
	}
	return err
}

// checkControlSocket refuses unless path is a socket (no link) owned by the
// owner with no group or other permission bits, in a directory checkControlDir
// accepts. A missing socket is ErrNoForegroundRun.
func checkControlSocket(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNoForegroundRun
	}
	if err != nil {
		return err
	}
	st := fi.Sys().(*syscall.Stat_t)
	if fi.Mode().Type() != fs.ModeSocket || st.Uid != controlOwner() || fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s", ErrControlUntrusted, path)
	}
	return checkControlDir(filepath.Dir(path))
}

// checkControlDir is checkTrustedDir for the control endpoint's owner.
func checkControlDir(dir string) error {
	return checkTrustedDir(dir, controlOwner(), ErrControlUntrusted)
}

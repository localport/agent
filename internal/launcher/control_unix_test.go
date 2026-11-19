//go:build linux || darwin

package launcher

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// controlAt points the control endpoint at a fresh directory owned by the
// test's uid, which stands in for root.
func controlAt(t *testing.T) string {
	t.Helper()
	// A short directory: socket paths are limited to about 100 bytes.
	dir, err := os.MkdirTemp("", "ctl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	prevSocket, prevOwner := controlSocket, controlOwner
	t.Cleanup(func() { controlSocket, controlOwner = prevSocket, prevOwner })
	controlSocket = filepath.Join(dir, "run", "control.sock")
	uid := uint32(os.Getuid())
	controlOwner = func() uint32 { return uid }
	return controlSocket
}

// serveControl listens and serves until the test ends, counting reloads.
func serveControl(t *testing.T) (*ControlListener, *atomic.Int32) {
	t.Helper()
	ctl, err := ListenControl()
	if err != nil {
		t.Fatal(err)
	}
	return ctl, serveOn(t, ctl)
}

// serveOn serves ctl until the test ends, counting reloads.
func serveOn(t *testing.T, ctl *ControlListener) *atomic.Int32 {
	t.Helper()
	var reloads atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ctl.Serve(ctx, func() bool { reloads.Add(1); return true }, t.Logf)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = ctl.Close()
	})
	return &reloads
}

// A reload request from the owner is answered once the reload is queued; the
// socket is 0600 in a directory the endpoint created.
func TestControlReloadRoundTrip(t *testing.T) {
	path := controlAt(t)
	_, reloads := serveControl(t)
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket %v, %v; want mode 0600", fi, err)
	}
	if err := RequestReload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reloads.Load() != 1 {
		t.Fatalf("reloads = %d, want 1", reloads.Load())
	}
}

// A peer that is not the owner is closed without a byte and queues no
// reload. Linux resets a connection closed with its request unread, macOS
// ends it; the client reads either as no answer.
func TestControlRefusesAnotherPeer(t *testing.T) {
	path := controlAt(t)
	ctl, err := ListenControl()
	if err != nil {
		t.Fatal(err)
	}
	ctl.peer++
	reloads := serveOn(t, ctl)
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, controlReload)
	if b, err := io.ReadAll(c); (err != nil && !errors.Is(err, syscall.ECONNRESET)) || len(b) != 0 {
		t.Fatalf("another peer read %q, %v; want a close without a byte", b, err)
	}
	if reloads.Load() != 0 {
		t.Fatalf("another peer queued %d reloads", reloads.Load())
	}
}

// A run that cannot read the peer's credentials answers refused, which the
// client returns as ErrControlRefused, and queues no reload.
func TestControlRefusalOfUnreadableCredentialsIsAnswered(t *testing.T) {
	controlAt(t)
	prev := controlPeerCred
	t.Cleanup(func() { controlPeerCred = prev })
	controlPeerCred = func(*net.UnixConn) (uint32, int, error) { return 0, 0, errors.New("getsockopt failed") }
	_, reloads := serveControl(t)
	if err := RequestReload(context.Background()); !errors.Is(err, ErrControlRefused) {
		t.Fatalf("RequestReload = %v, want ErrControlRefused", err)
	}
	if reloads.Load() != 0 {
		t.Fatalf("a refused request queued %d reloads", reloads.Load())
	}
}

// The refusal is written only after the request arrives.
func TestControlRefusalWaitsForTheRequest(t *testing.T) {
	path := controlAt(t)
	prev := controlPeerCred
	t.Cleanup(func() { controlPeerCred = prev })
	controlPeerCred = func(*net.UnixConn) (uint32, int, error) { return 0, 0, errors.New("getsockopt failed") }
	serveControl(t)
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if b, err := io.ReadAll(c); len(b) != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("before the request the run answered %q, %v; want nothing until the request", b, err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, controlReload); err != nil {
		t.Fatal(err)
	}
	if ans, err := readAnswer(c); err != nil || ans != controlRefused {
		t.Fatalf("answer %q, %v; want %q", ans, err, controlRefused)
	}
}

// An unknown request queues no reload and gets no answer.
func TestControlRefusesAnUnknownRequest(t *testing.T) {
	path := controlAt(t)
	_, reloads := serveControl(t)
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, "stop!!\n")
	if b, _ := io.ReadAll(c); len(b) != 0 || reloads.Load() != 0 {
		t.Fatalf("unknown request answered %q, reloads %d", b, reloads.Load())
	}
}

// No socket, or one a crashed run left, is ErrNoForegroundRun.
func TestRequestReloadWithoutARun(t *testing.T) {
	path := controlAt(t)
	if err := RequestReload(context.Background()); !errors.Is(err, ErrNoForegroundRun) {
		t.Fatalf("no socket: %v, want ErrNoForegroundRun", err)
	}
	ctl, err := ListenControl()
	if err != nil {
		t.Fatal(err)
	}
	// A crash: every descriptor goes, the path stays.
	_ = ctl.ln.Close()
	if _, err := os.Lstat(path); err != nil {
		t.Fatal(err)
	}
	if err := RequestReload(context.Background()); !errors.Is(err, ErrNoForegroundRun) {
		t.Fatalf("left socket: %v, want ErrNoForegroundRun", err)
	}
	// The next run replaces it.
	_, reloads := serveControl(t)
	if err := RequestReload(context.Background()); err != nil || reloads.Load() != 1 {
		t.Fatalf("after the replacement: %v, reloads %d", err, reloads.Load())
	}
}

// The client refuses a socket open to others, one not owned by the owner and
// a directory others may write, before connecting.
func TestRequestReloadRefusesAnUntrustedEndpoint(t *testing.T) {
	path := controlAt(t)
	_, reloads := serveControl(t)
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	if err := RequestReload(context.Background()); !errors.Is(err, ErrControlUntrusted) {
		t.Fatalf("socket mode 0660: %v, want ErrControlUntrusted", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o775); err != nil {
		t.Fatal(err)
	}
	if err := RequestReload(context.Background()); !errors.Is(err, ErrControlUntrusted) {
		t.Fatalf("group-writable directory: %v, want ErrControlUntrusted", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	controlOwner = func() uint32 { return uid + 1 }
	if err := RequestReload(context.Background()); !errors.Is(err, ErrControlUntrusted) {
		t.Fatalf("socket of another owner: %v, want ErrControlUntrusted", err)
	}
	if reloads.Load() != 0 {
		t.Fatalf("an untrusted endpoint got %d reloads", reloads.Load())
	}
}

// ListenControl refuses a directory others may write and a non-socket at the
// socket's path.
func TestListenControlRefusesAnUnsafePath(t *testing.T) {
	path := controlAt(t)
	dir := filepath.Dir(path)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenControl(); !errors.Is(err, ErrControlUntrusted) {
		t.Fatalf("world-writable directory: %v, want ErrControlUntrusted", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenControl(); !errors.Is(err, ErrControlUntrusted) {
		t.Fatalf("regular file at the socket path: %v, want ErrControlUntrusted", err)
	}
}

// A trusted directory is owned by the expected uid and writable by neither
// group nor others: one owned by another uid, a group- or world-writable one
// and a link are refused.
func TestCheckTrustedDir(t *testing.T) {
	uid := uint32(os.Getuid())
	dir := t.TempDir()
	if err := checkTrustedDir(dir, uid, ErrStatusUntrusted); err != nil {
		t.Fatalf("own directory: %v", err)
	}
	if err := checkTrustedDir(dir, uid+1, ErrStatusUntrusted); !errors.Is(err, ErrStatusUntrusted) {
		t.Fatalf("directory of another owner: %v, want ErrStatusUntrusted", err)
	}
	if err := os.Chmod(dir, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := checkTrustedDir(dir, uid, ErrStatusUntrusted); !errors.Is(err, ErrStatusUntrusted) {
		t.Fatalf("group-writable directory: %v, want ErrStatusUntrusted", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := checkTrustedDir(link, uid, ErrStatusUntrusted); !errors.Is(err, ErrStatusUntrusted) {
		t.Fatalf("link to a directory: %v, want ErrStatusUntrusted", err)
	}
}

// Socket activation: the socket OpenControl opens takes a connect before the
// serving process accepts, which then answers it, and the endpoint refuses
// once every descriptor is closed.
func TestControlQueuesUntilTheRunAccepts(t *testing.T) {
	path := controlAt(t)
	sock, err := OpenControl()
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	// Connected before anything accepts: the request waits in the backlog.
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("connect before the run accepts: %v, want it queued", err)
	}
	defer c.Close()
	// The serving process gets its own descriptor, as the child does.
	passed, err := dupFile(sock.File())
	if err != nil {
		t.Fatal(err)
	}
	ctl, err := ControlListenerOn(passed)
	if err != nil {
		t.Fatal(err)
	}
	// Root closes its copy once the child has started.
	_ = sock.File().Close()
	reloads := serveOn(t, ctl)
	if err := reloadOn(c); err != nil || reloads.Load() != 1 {
		t.Fatalf("queued request: %v, reloads %d; want nil and 1", err, reloads.Load())
	}
	_ = ctl.Close()
	if err := RequestReload(context.Background()); !errors.Is(err, ErrNoForegroundRun) {
		t.Fatalf("after the listener closed: %v, want ErrNoForegroundRun", err)
	}
}

// While root enrols, the socket it opened answers that the run is starting;
// once root stops answering, a request waits in the backlog and the process
// it hands the socket to answers it.
func TestControlAnswersStartingUntilTheHandOff(t *testing.T) {
	path := controlAt(t)
	sock, err := OpenControl()
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	stop, err := sock.ServeStarting(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if err := RequestReload(context.Background()); !errors.Is(err, ErrRunStarting) {
		t.Fatalf("request while root enrols: %v, want ErrRunStarting", err)
	}
	stop()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("connect after root stopped answering: %v, want it queued", err)
	}
	defer c.Close()
	passed, err := dupFile(sock.File())
	if err != nil {
		t.Fatal(err)
	}
	ctl, err := ControlListenerOn(passed)
	if err != nil {
		t.Fatal(err)
	}
	reloads := serveOn(t, ctl)
	if err := reloadOn(c); err != nil || reloads.Load() != 1 {
		t.Fatalf("request queued during the hand-off: %v, reloads %d; want nil and 1", err, reloads.Load())
	}
}

// A request queued for a run that exits before it accepts is
// ErrNoForegroundRun: the connection is reset or closed without an answer.
func TestControlRequestToARunThatExitsIsNoRun(t *testing.T) {
	path := controlAt(t)
	sock, err := OpenControl()
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// The run exits without accepting: its only descriptor closes.
	_ = sock.File().Close()
	if err := reloadOn(c); !errors.Is(err, ErrNoForegroundRun) {
		t.Fatalf("request to a run that exited: %v, want ErrNoForegroundRun", err)
	}
}

// ControlListenerOn refuses a descriptor that is not the control socket.
func TestControlListenerOnRefusesAnotherSocket(t *testing.T) {
	controlAt(t)
	if err := os.Mkdir(filepath.Dir(controlSocket), 0o755); err != nil {
		t.Fatal(err)
	}
	other, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(filepath.Dir(controlSocket), "other.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	f, err := other.File()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ControlListenerOn(f); !errors.Is(err, errNotControlSocket) {
		t.Fatalf("another socket: %v, want errNotControlSocket", err)
	}
}

// dupFile is a second descriptor of f.
func dupFile(f *os.File) (*os.File, error) {
	fd, err := unix.Dup(int(f.Fd()))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), f.Name()), nil
}

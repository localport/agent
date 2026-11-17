//go:build cgo

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/localport/agent/internal/launcher"
)

// listeners returns the launcher socket and the status endpoint: the sockets
// systemd passed (localport-session.socket and localport-status.socket,
// matched by FileDescriptorName), or both bound by the launcher itself
// (OpenRC, procd): inside a root-owned 0750 directory of group gid, mode
// 0660, created with the umask set before bind so it is never wider.
func listeners(gid uint32) (session, status *net.UnixListener, err error) {
	fds, err := systemdFDs(os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS"), os.Getenv("LISTEN_FDNAMES"), os.Getpid())
	if err != nil {
		return nil, nil, err
	}
	if fds != nil {
		os.Unsetenv("LISTEN_PID")
		os.Unsetenv("LISTEN_FDS")
		os.Unsetenv("LISTEN_FDNAMES")
		if session, err = passedListener(fds[fdNameSession], "localport-session.socket"); err != nil {
			return nil, nil, err
		}
		if status, err = passedListener(fds[fdNameStatus], "localport-status.socket"); err != nil {
			session.Close()
			return nil, nil, err
		}
		return session, status, nil
	}
	if session, err = bindSocket(launcher.SocketPath, gid); err != nil {
		return nil, nil, err
	}
	if status, err = bindSocket(launcher.StatusSocketPath, gid); err != nil {
		session.Close()
		return nil, nil, err
	}
	return session, status, nil
}

func passedListener(fd int, name string) (*net.UnixListener, error) {
	f := os.NewFile(uintptr(fd), name)
	ln, err := net.FileListener(f)
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("the socket systemd passed (%s): %w", name, err)
	}
	ul, ok := ln.(*net.UnixListener)
	if !ok {
		ln.Close()
		return nil, fmt.Errorf("the socket systemd passed (%s) is not a Unix socket", name)
	}
	return ul, nil
}

func bindSocket(path string, gid uint32) (*net.UnixListener, error) {
	dir := filepath.Dir(path)
	if err := os.Mkdir(dir, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	st := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || st.Uid != 0 {
		return nil, fmt.Errorf("%s is not a root-owned directory", dir)
	}
	if err := os.Chown(dir, 0, int(gid)); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		return nil, err
	}
	// Only the launcher binds here; a leftover socket is from its last run.
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&fs.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	old := unix.Umask(0o117)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	unix.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chown(path, 0, int(gid)); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

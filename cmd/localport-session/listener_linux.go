//go:build cgo

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/localport/agent/internal/launcher"
)

// systemdListenFD is the first descriptor systemd passes (sd_listen_fds).
const systemdListenFD = 3

// listener returns the socket systemd passed (localport-session.socket), or
// binds launcher.SocketPath itself (OpenRC, procd): inside a root-owned 0750
// directory of group gid, mode 0660, created with the umask set before bind
// so it is never wider.
func listener(gid uint32) (*net.UnixListener, error) {
	if os.Getenv("LISTEN_PID") == strconv.Itoa(os.Getpid()) && os.Getenv("LISTEN_FDS") == "1" {
		os.Unsetenv("LISTEN_PID")
		os.Unsetenv("LISTEN_FDS")
		os.Unsetenv("LISTEN_FDNAMES")
		f := os.NewFile(systemdListenFD, "localport-session.socket")
		ln, err := net.FileListener(f)
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("the socket systemd passed: %w", err)
		}
		ul, ok := ln.(*net.UnixListener)
		if !ok {
			ln.Close()
			return nil, errors.New("the socket systemd passed is not a Unix socket")
		}
		return ul, nil
	}
	return bindSocket(gid)
}

func bindSocket(gid uint32) (*net.UnixListener, error) {
	dir := filepath.Dir(launcher.SocketPath)
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
	if fi, err := os.Lstat(launcher.SocketPath); err == nil {
		if fi.Mode()&fs.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", launcher.SocketPath)
		}
		if err := os.Remove(launcher.SocketPath); err != nil {
			return nil, err
		}
	}
	old := unix.Umask(0o117)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: launcher.SocketPath, Net: "unix"})
	unix.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chown(launcher.SocketPath, 0, int(gid)); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

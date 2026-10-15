//go:build !windows

package access

import (
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// socketMask gives a new socket mode 0600.
const socketMask = 0o177

// umaskMu serializes umask changes, which are process-wide.
var umaskMu sync.Mutex

// listenSocket binds a 0600 Unix socket. The mode comes from the umask at bind
// time, as in OpenSSH. A chmod after bind leaves a window in which another user
// can connect and stay in the accept queue.
func listenSocket(path string) (net.Listener, error) {
	if err := removeStaleSocket(path); err != nil {
		return nil, err
	}
	umaskMu.Lock()
	previous := syscall.Umask(socketMask)
	ln, err := net.Listen("unix", path)
	syscall.Umask(previous)
	umaskMu.Unlock()
	if err != nil {
		return nil, err
	}
	return ln, nil
}

// removeStaleSocket removes a socket with no listener, as left by a killed
// process. A live socket or a non-socket file is an error.
func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a socket", path)
	}
	if conn, dialErr := net.DialTimeout("unix", path, time.Second); dialErr == nil {
		_ = conn.Close()
		return fmt.Errorf("%s is in use by another process", path)
	}
	return os.Remove(path)
}

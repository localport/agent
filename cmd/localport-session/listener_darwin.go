//go:build cgo

package main

/*
#include <launch.h>
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"github.com/localport/agent/internal/launcher"
)

// The Sockets keys of the io.localport.session plist: the launcher socket
// and the status endpoint.
const (
	launchdSocketName = "Listeners"
	launchdStatusName = "Status"
)

// listeners returns the sockets launchd bound from the plist's Sockets
// entries (launch_activate_socket(3)); launchd owns their paths, owners and
// modes. Only the launcher socket is required: without the status endpoint
// status is nil and statusErr says why.
func listeners(uint32) (session, status *net.UnixListener, statusErr, err error) {
	if session, err = activatedSocket(launchdSocketName); err != nil {
		return nil, nil, nil, err
	}
	status, statusErr = activatedSocket(launchdStatusName)
	return session, status, statusErr, nil
}

func activatedSocket(key string) (*net.UnixListener, error) {
	name := C.CString(key)
	defer C.free(unsafe.Pointer(name))
	var fds *C.int
	var n C.size_t
	if rc := C.launch_activate_socket(name, &fds, &n); rc != 0 {
		return nil, fmt.Errorf("launch_activate_socket: %w", syscall.Errno(rc))
	}
	defer C.free(unsafe.Pointer(fds))
	all := unsafe.Slice(fds, int(n))
	if n != 1 {
		for _, fd := range all {
			_ = syscall.Close(int(fd))
		}
		return nil, fmt.Errorf("launchd passed %d sockets for %s, want 1", int(n), key)
	}
	f := os.NewFile(uintptr(all[0]), "io.localport.session "+key)
	ln, err := net.FileListener(f)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	ul, ok := ln.(*net.UnixListener)
	if !ok {
		ln.Close()
		return nil, errors.New("the socket launchd passed is not a Unix socket")
	}
	return ul, nil
}

// sessionFullDiskAccess is the launcher's per-request Full Disk Access
// reading (launcher.Server.FullDiskAccess).
var sessionFullDiskAccess = launcher.ReadFullDiskAccess

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
	"io/fs"
	"net"
	"os"
	"syscall"
	"unsafe"
)

// launchdSocketName is the Sockets key of the io.localport.session plist.
const launchdSocketName = "Listeners"

// listener returns the socket launchd bound from the plist's Sockets entry
// (launch_activate_socket(3)); launchd owns its path, owner and mode.
func listener(uint32) (*net.UnixListener, error) {
	name := C.CString(launchdSocketName)
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
		return nil, fmt.Errorf("launchd passed %d sockets, want 1", int(n))
	}
	f := os.NewFile(uintptr(all[0]), "io.localport.session")
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

// tccDatabase is readable only by a process holding Full Disk Access.
const tccDatabase = "/Library/Application Support/com.apple.TCC/TCC.db"

// fullDiskAccess reports whether the launcher holds Full Disk Access, by
// opening a file TCC protects for every process without it.
func fullDiskAccess() string {
	f, err := os.Open(tccDatabase)
	switch {
	case err == nil:
		_ = f.Close()
		return "granted"
	case errors.Is(err, fs.ErrPermission):
		return "denied"
	}
	return "unknown"
}

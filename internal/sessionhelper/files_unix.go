//go:build unix

package sessionhelper

import (
	"os"
	"syscall"
)

// openNonblock keeps opening a FIFO from blocking until a writer appears;
// openRegular then refuses it as not a regular file.
const openNonblock = syscall.O_NONBLOCK

// checkOpened has nothing to add on Unix: the fstat in openRegular refuses
// FIFOs, sockets and devices.
func checkOpened(*os.File) error { return nil }

//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package ui

import (
	"os"
	"syscall"
	"unsafe"
)

// enterRaw clears ECHO and ICANON on f so typed bytes and arrow-key
// escape sequences from mouse-wheel scrolling never display or buffer
// into the rendered frame. ISIG stays on, so Ctrl+C still raises SIGINT
// through the kernel instead of arriving as a literal byte.
func enterRaw(f *os.File) (restore func(), err error) {
	var orig syscall.Termios
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TIOCGETA, uintptr(unsafe.Pointer(&orig))); e != 0 {
		return nil, e
	}
	mod := orig
	mod.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.ECHONL | syscall.IEXTEN
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TIOCSETA, uintptr(unsafe.Pointer(&mod))); e != 0 {
		return nil, e
	}
	return func() {
		syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TIOCSETA, uintptr(unsafe.Pointer(&orig)))
	}, nil
}

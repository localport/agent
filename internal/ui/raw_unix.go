//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package ui

import (
	"os"

	"golang.org/x/sys/unix"
)

// enterRaw clears ECHO and ICANON on f so typed input and scroll escape
// sequences do not appear in the frame. ISIG stays on, so Ctrl+C still raises
// SIGINT. The ioctl request constants are per platform.
func enterRaw(f *os.File) (restore func(), err error) {
	fd := int(f.Fd())
	orig, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		return nil, err
	}
	mod := *orig
	mod.Lflag &^= unix.ECHO | unix.ICANON | unix.ECHONL | unix.IEXTEN
	if err := unix.IoctlSetTermios(fd, ioctlWriteTermios, &mod); err != nil {
		return nil, err
	}
	return func() { _ = unix.IoctlSetTermios(fd, ioctlWriteTermios, orig) }, nil
}

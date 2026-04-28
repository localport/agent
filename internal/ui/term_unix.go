//go:build unix

package ui

import (
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

type winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

// TermSize returns the terminal's columns and rows, falling back to 80x24
// when the ioctl can't be made (e.g. piped output, or f is not a tty).
func TermSize(f *os.File) (cols, rows int) {
	if f == nil {
		return 80, 24
	}
	var ws winsize
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(&ws)),
	)
	if errno != 0 || ws.Col == 0 {
		return 80, 24
	}
	return int(ws.Col), int(ws.Row)
}

// notifyResize delivers a signal each time the terminal is resized.
func notifyResize() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	return ch, func() { signal.Stop(ch); close(ch) }
}

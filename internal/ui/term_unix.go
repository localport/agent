//go:build unix

package ui

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

// TermSize returns the terminal columns and rows, or 80x24 when f is not a
// terminal.
func TermSize(f *os.File) (cols, rows int) {
	if f == nil {
		return 80, 24
	}
	ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil || ws.Col == 0 {
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

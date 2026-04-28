//go:build windows

package ui

import "os"

// Windows builds use a static 80x24 size. The console host can ship its
// own SIGWINCH-equivalent later if needed.
func TermSize(_ *os.File) (cols, rows int) { return 80, 24 }

func notifyResize() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal)
	return ch, func() {}
}

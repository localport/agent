//go:build windows

package ui

import "os"

// TermSize is 80x24 on Windows, and notifyResize reports no resize.
func TermSize(_ *os.File) (cols, rows int) { return 80, 24 }

func notifyResize() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal)
	return ch, func() {}
}

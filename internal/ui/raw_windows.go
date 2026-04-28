//go:build windows

package ui

import "os"

// enterRaw is a no-op on Windows. The TUI relies on Windows console
// input being non-echoed by default when stdin is redirected; if a
// console allocation is detected this can be filled in via
// SetConsoleMode(stdin, ENABLE_VIRTUAL_TERMINAL_INPUT) without echo.
func enterRaw(_ *os.File) (func(), error) {
	return func() {}, nil
}

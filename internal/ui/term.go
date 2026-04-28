package ui

import (
	"fmt"
	"os"
)

// ANSI control sequences. Hand-rolled to avoid pulling a TUI dependency.
const (
	AltScreenOn   = "\x1b[?1049h"
	AltScreenOff  = "\x1b[?1049l"
	CursorHide    = "\x1b[?25l"
	CursorShow    = "\x1b[?25h"
	ClearScreen   = "\x1b[2J"
	ClearLine     = "\x1b[2K"
	SaveCursor    = "\x1b7"
	RestoreCursor = "\x1b8"

	SGRReset = "\x1b[0m"
	SGRBold  = "\x1b[1m"
	SGRDim   = "\x1b[2m"

	FgRed     = "\x1b[31m"
	FgGreen   = "\x1b[32m"
	FgYellow  = "\x1b[33m"
	FgBlue    = "\x1b[34m"
	FgMagenta = "\x1b[35m"
	FgCyan    = "\x1b[36m"
	FgWhite   = "\x1b[37m"
)

func MoveTo(row, col int) string          { return fmt.Sprintf("\x1b[%d;%dH", row, col) }
func SetScrollRegion(top, bot int) string { return fmt.Sprintf("\x1b[%d;%dr", top, bot) }
func ResetScrollRegion() string           { return "\x1b[r" }

// IsTTY reports whether f refers to a character device.
func IsTTY(f *os.File) bool {
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

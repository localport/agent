package ui

import (
	"fmt"
	"os"
)

// ANSI screen control sequences. Color sequences are in color.go.
const (
	AltScreenOn  = "\x1b[?1049h"
	AltScreenOff = "\x1b[?1049l"
	CursorHide   = "\x1b[?25l"
	CursorShow   = "\x1b[?25h"
	ClearScreen  = "\x1b[2J"
	ClearLine    = "\x1b[2K"
)

func MoveTo(row, col int) string { return fmt.Sprintf("\x1b[%d;%dH", row, col) }

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

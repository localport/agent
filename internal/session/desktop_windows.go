//go:build windows

package session

import (
	"errors"

	"golang.org/x/sys/windows"
)

// errConnRefused reports whether a dial failed because nothing listens.
func errConnRefused(err error) bool { return errors.Is(err, windows.WSAECONNREFUSED) }

//go:build !windows

package session

import (
	"errors"
	"syscall"
)

// errConnRefused reports whether a dial failed because nothing listens.
func errConnRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

//go:build !windows

package errcode

import (
	"errors"
	"syscall"
)

func addrInUse(err error) bool { return errors.Is(err, syscall.EADDRINUSE) }

//go:build !linux && !darwin

package cli

import (
	"context"
	"errors"
)

// startLogFile is unsupported here: the Windows service logs to the event
// log, and no generated definition passes --log-file.
func startLogFile(context.Context, string) error {
	return errors.New("--log-file is supported on Linux and macOS only")
}

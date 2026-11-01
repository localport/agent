//go:build linux || darwin

package cli

import (
	"context"

	"github.com/localport/agent/internal/logfile"
)

// startLogFile points stdout and stderr at path and rotates it until ctx
// ends (run --log-file, under launchd and OpenRC).
func startLogFile(ctx context.Context, path string) error {
	l, err := logfile.Open(path)
	if err != nil {
		return err
	}
	go l.Run(ctx)
	return nil
}

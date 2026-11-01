//go:build !linux && !darwin

package cli

import (
	"context"
	"errors"

	"github.com/localport/agent/internal/launcher"
)

// probe fails: this platform has no session launcher.
var probe = func(context.Context) (launcher.Probe, error) {
	return launcher.Probe{}, errors.New("no session launcher on this platform")
}

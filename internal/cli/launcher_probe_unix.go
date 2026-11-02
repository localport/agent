//go:build linux || darwin || windows

package cli

import (
	"context"

	"github.com/localport/agent/internal/launcher"
)

// probe is the launcher client's Probe; tests replace it.
var probe = func(ctx context.Context) (launcher.Probe, error) {
	return launcher.DefaultClient().Probe(ctx)
}

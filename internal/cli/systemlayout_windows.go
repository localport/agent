package cli

import (
	"context"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/service"
)

// prepareSystemLayout is never reached on Windows, whose system config is
// not System; the Administrators-owned layout needs no preparation.
func prepareSystemLayout(context.Context, config.LocalConfigFile, service.Manager, string) error {
	return nil
}

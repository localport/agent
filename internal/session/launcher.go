package session

import (
	"context"
	"os"

	"github.com/localport/agent/internal/launcher"
)

// Launcher starts sessions as the device's logins: the root session
// launcher (launcher.Client) in production.
type Launcher interface {
	Probe(ctx context.Context) (launcher.Probe, error)
	Start(ctx context.Context, req launcher.Request, channel *os.File) (*launcher.Session, error)
}

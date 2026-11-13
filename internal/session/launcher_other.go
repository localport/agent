//go:build !linux && !darwin && !windows

package session

import (
	"errors"
	"os"
)

// launcherFor returns nil: builds other than Linux, macOS and Windows have no
// session launcher, so terminal, ssh and files certificates are refused;
// desktop sessions need none.
func launcherFor(Launcher) Launcher { return nil }

// newSessionChannel is never reached without a launcher.
func newSessionChannel() (ours, theirs *os.File, pipe string, err error) {
	return nil, nil, "", errors.ErrUnsupported
}

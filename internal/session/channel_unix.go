//go:build linux || darwin

package session

import (
	"os"

	"github.com/localport/agent/internal/launcher"
)

// newSessionChannel returns the agent's end of a session channel and the
// helper's end, which Start passes to the launcher as a descriptor. pipe is
// always empty.
func newSessionChannel() (ours, theirs *os.File, pipe string, err error) {
	ours, theirs, err = launcher.SocketPair()
	return ours, theirs, "", err
}

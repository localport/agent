//go:build windows

package session

import (
	"os"

	"github.com/localport/agent/internal/launcher"
)

// newSessionChannel returns the agent's end of a session channel, a pipe
// the helper opens by name; theirs is always nil.
func newSessionChannel() (ours, theirs *os.File, pipe string, err error) {
	ours, pipe, err = launcher.NewSessionChannel()
	return ours, nil, pipe, err
}

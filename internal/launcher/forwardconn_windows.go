//go:build windows

package launcher

import "os"

// newForwardTransport is the agent's end of a forward helper's session pipe.
func newForwardTransport(channel *os.File, log func(string, ...any)) (forwardTransport, error) {
	return newFrameForwardTransport(channel, log), nil
}

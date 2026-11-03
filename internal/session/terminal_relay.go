//go:build linux || darwin || windows

package session

import "github.com/localport/agent/internal/launcher"

// launcherFor returns the launcher that serves channels: l, or the launcher
// socket (Unix) or pipe (Windows) when l is nil.
func launcherFor(l Launcher) Launcher {
	if l == nil {
		return launcher.DefaultClient()
	}
	return l
}

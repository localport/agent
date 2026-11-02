//go:build !linux && !darwin && !windows

package session

// kindFor returns the session kind that serves kind, or nil when this build
// has none. Builds other than Linux, macOS and Windows serve no kind.
func kindFor(string, Launcher) prepareKind { return nil }

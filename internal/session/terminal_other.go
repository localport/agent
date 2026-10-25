//go:build !linux && !darwin

package session

// kindFor returns the session kind that serves kind, or nil when this build
// has none. Builds other than Linux and macOS (Windows) serve no kind.
func kindFor(string) prepareKind { return nil }

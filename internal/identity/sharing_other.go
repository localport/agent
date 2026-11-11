//go:build !windows

package identity

// isSharingViolation is false off Windows, where an open handle never blocks a
// delete.
func isSharingViolation(error) bool { return false }

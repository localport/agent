//go:build !linux

package security

// HardenProcess is a no-op outside Linux, which has no portable equivalent of
// PR_SET_DUMPABLE. On macOS and Windows a same-user debugger can read the
// token.
func HardenProcess() {}

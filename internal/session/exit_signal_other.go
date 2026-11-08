//go:build !unix

package session

// signalName has nothing to name: only a Unix helper reports a signal.
func signalName(int) string { return "" }

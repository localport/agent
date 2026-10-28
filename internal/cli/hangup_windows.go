//go:build windows

package cli

// ignoreHangupSignals does nothing: Windows has no SIGHUP or SIGPIPE.
func ignoreHangupSignals() {}

// writeSystemLog does nothing: the command's outcome is on its console.
func writeSystemLog(bool, string) {}

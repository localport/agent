package cli

import "strings"

// ignoreHangup sets the hangup-safe dispositions for the rest of the process;
// systemLog writes one line to the system log, at error priority when failed
// is set. Tests replace both, so the test process keeps its own dispositions
// and writes nothing to the host's log.
var (
	ignoreHangup = ignoreHangupSignals
	systemLog    = writeSystemLog
)

// logOutcome records how a hangup-safe command run as root ended in the
// system log, where it stays readable after the terminal the command ran in
// is gone. The record quotes the error only when withCause is set: connect
// passes false, because its errors can quote its arguments.
func logOutcome(command []string, err error, withCause bool) {
	line := "localport " + strings.Join(command, " ") + ": "
	switch {
	case err == nil:
		systemLog(false, line+"completed")
	case withCause:
		systemLog(true, line+"failed: "+err.Error())
	default:
		systemLog(true, line+"failed")
	}
}

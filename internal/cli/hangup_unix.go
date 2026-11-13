//go:build !windows

package cli

import (
	"errors"
	"fmt"
	"log/syslog"
	"net"
	"os"
	"os/signal"
	"syscall"
)

// ignoreHangupSignals makes a command that restarts or stops the device
// service safe to run from a terminal session that service serves: the
// session's hangup (SIGHUP) and its closed terminal (SIGPIPE on a write) do
// not stop the command halfway, and a failed write to stdout or stderr only
// returns an error, which the command does not check. The service manager
// commands it starts inherit the ignored dispositions across exec.
func ignoreHangupSignals() { signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE) }

// syslogSockets are the sockets syslog.New tries, in its order, over
// unixgram and then unix (log/syslog unixSyslog).
var syslogSockets = []string{"/dev/log", "/var/run/syslog", "/var/run/log"}

// writeSystemLog writes line to the system log. A host with no system log
// daemon listening gets no record and no message; any other failure prints
// one line to stderr.
func writeSystemLog(failed bool, line string) {
	w, err := syslog.New(syslog.LOG_USER|syslog.LOG_INFO, "localport")
	if err != nil {
		if cause := syslogDialError(syslogSockets, err); cause != nil {
			fmt.Fprintf(os.Stderr, "  could not write to the system log: %v\n", cause)
		}
		return
	}
	defer w.Close()
	if failed {
		err = w.Err(line)
	} else {
		err = w.Info(line)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "  could not write to the system log: %s\n", userText(err))
	}
}

// syslogDialError classifies a failed syslog.New, whose error does not say
// why, by dialing its sockets again. It returns nil when no socket has a
// daemon behind it (each dial fails with ENOENT or ECONNREFUSED, or
// EPROTOTYPE from the other socket type), the first other dial error, or
// newErr when a dial succeeds now.
func syslogDialError(sockets []string, newErr error) error {
	var cause error
	for _, network := range []string{"unixgram", "unix"} {
		for _, path := range sockets {
			conn, err := net.Dial(network, path)
			if err == nil {
				conn.Close()
				return newErr
			}
			absent := errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EPROTOTYPE)
			if !absent && cause == nil {
				cause = err
			}
		}
	}
	return cause
}

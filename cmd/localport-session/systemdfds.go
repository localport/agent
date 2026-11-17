package main

import (
	"fmt"
	"strconv"
	"strings"
)

// systemdListenFD is the first descriptor systemd passes (sd_listen_fds).
const systemdListenFD = 3

// The FileDescriptorName of each socket unit the launcher takes.
const (
	fdNameSession = "session" // localport-session.socket
	fdNameStatus  = "status"  // localport-status.socket
)

// systemdFDs maps the descriptors systemd passed to their
// FileDescriptorName, from LISTEN_PID, LISTEN_FDS and LISTEN_FDNAMES. It
// returns nil when systemd passed none to pid. Both names must be present
// once each; any other name is refused.
func systemdFDs(listenPID, listenFDs, fdNames string, pid int) (map[string]int, error) {
	if listenPID != strconv.Itoa(pid) {
		return nil, nil
	}
	n, err := strconv.Atoi(listenFDs)
	if err != nil || n < 1 {
		return nil, fmt.Errorf("LISTEN_FDS %q is not a descriptor count", listenFDs)
	}
	names := strings.Split(fdNames, ":")
	if len(names) != n {
		return nil, fmt.Errorf("systemd passed %d sockets named %q; set FileDescriptorName on each socket unit", n, fdNames)
	}
	fds := make(map[string]int, n)
	for i, name := range names {
		if name != fdNameSession && name != fdNameStatus {
			return nil, fmt.Errorf("systemd passed a socket named %q, want %s or %s", name, fdNameSession, fdNameStatus)
		}
		if _, dup := fds[name]; dup {
			return nil, fmt.Errorf("systemd passed two sockets named %q", name)
		}
		fds[name] = systemdListenFD + i
	}
	for _, name := range []string{fdNameSession, fdNameStatus} {
		if _, ok := fds[name]; !ok {
			return nil, fmt.Errorf("systemd passed no socket named %q; reinstall the service: sudo localport service install", name)
		}
	}
	return fds, nil
}

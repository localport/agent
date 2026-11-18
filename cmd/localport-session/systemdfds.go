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

// reinstallUnits is the remedy for socket units that do not match this
// launcher: service install writes them again.
const reinstallUnits = "reinstall the service: sudo localport service install"

// systemdFDs maps the descriptors systemd passed to their
// FileDescriptorName, from LISTEN_PID, LISTEN_FDS and LISTEN_FDNAMES. It
// returns nil when systemd passed none to pid. The session name must be
// present and the status name may be, each once; any other name is refused.
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
		return nil, fmt.Errorf("systemd passed %d sockets named %q; %s", n, fdNames, reinstallUnits)
	}
	fds := make(map[string]int, n)
	for i, name := range names {
		if name != fdNameSession && name != fdNameStatus {
			return nil, fmt.Errorf("systemd passed a socket named %q, want %s or %s; %s", name, fdNameSession, fdNameStatus, reinstallUnits)
		}
		if _, dup := fds[name]; dup {
			return nil, fmt.Errorf("systemd passed two sockets named %q; %s", name, reinstallUnits)
		}
		fds[name] = systemdListenFD + i
	}
	if _, ok := fds[fdNameSession]; !ok {
		return nil, fmt.Errorf("systemd passed no socket named %q; %s", fdNameSession, reinstallUnits)
	}
	return fds, nil
}

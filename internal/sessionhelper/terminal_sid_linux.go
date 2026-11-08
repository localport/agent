package sessionhelper

import "golang.org/x/sys/unix"

// ioctlGetSession reads a terminal's session id.
const ioctlGetSession = unix.TIOCGSID

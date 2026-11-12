//go:build linux || darwin

package launcher

import "time"

// StartTimeout bounds a session start at the client: the launcher's own
// helper start bound plus slack for the connection.
const StartTimeout = helperStartTimeout + 5*time.Second

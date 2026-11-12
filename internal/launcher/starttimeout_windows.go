package launcher

import "time"

// StartTimeout bounds a session start at the client: the launcher's helper
// start bound, its profile load bound and slack for the connection.
const StartTimeout = helperStartTimeout + profileStartTimeout + 5*time.Second

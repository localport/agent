package launcher

// The launcher socket per platform. Service definitions on every build name
// them; SocketPath is this platform's.
const (
	// LinuxSocketPath: systemd creates it from localport-session.socket;
	// under OpenRC and procd the launcher binds it itself.
	LinuxSocketPath = "/run/localport/session.sock"
	// DarwinSocketPath: launchd binds it from the io.localport.session
	// Sockets entry.
	DarwinSocketPath = "/var/run/localport/session.sock"

	// LinuxStatusSocketPath is the status endpoint: systemd creates it from
	// localport-status.socket; under OpenRC and procd the launcher binds it.
	LinuxStatusSocketPath = "/run/localport/status.sock"
	// DarwinStatusSocketPath: launchd binds it from the io.localport.session
	// Sockets entry Status.
	DarwinStatusSocketPath = "/var/run/localport/status.sock"
)

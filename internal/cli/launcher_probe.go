package cli

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/session"
)

// sessionProbe is what the session launcher reported at start, for the
// device registration. Empty fields are unknown: no launcher answered.
type sessionProbe struct {
	sessionAuth    string
	fullDiskAccess string
}

// sessionLauncher starts the devices' terminal sessions; nil is the launcher
// socket. Tests replace it.
var sessionLauncher session.Launcher

// launcherProbeTimeout bounds the start-time probe.
const launcherProbeTimeout = 5 * time.Second

// probeLauncher asks the session launcher what it offers. A launcher that
// does not answer is logged and reported as unknown: the registration
// carries no session_auth.
func probeLauncher(ctx context.Context, logEvent func(string)) sessionProbe {
	ctx, cancel := context.WithTimeout(ctx, launcherProbeTimeout)
	defer cancel()
	p, err := probe(ctx)
	if err != nil {
		logEvent(fmt.Sprintf("session: the session launcher did not answer its probe: %v", err))
		return sessionProbe{}
	}
	// Windows logs on by S4U; the dashboard shows when a joined device found
	// no domain controller, so domain logins fail.
	if runtime.GOOS == "windows" {
		switch p.S4U {
		case launcher.S4ULocal, launcher.S4UDomain:
			return sessionProbe{sessionAuth: "s4u"}
		case launcher.S4UDomainUnreachable:
			return sessionProbe{sessionAuth: "s4u_domain_unreachable"}
		}
		return sessionProbe{}
	}
	out := sessionProbe{sessionAuth: "no_pam"}
	if p.PAM {
		out.sessionAuth = "pam"
	}
	if runtime.GOOS == "darwin" {
		out.fullDiskAccess = p.FullDiskAccess
	}
	return out
}

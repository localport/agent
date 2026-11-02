package cli

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/localport/agent/internal/session"
)

// sessionProbe is what the session launcher reported at start, for the
// device registration. Empty fields are unknown: no launcher answered.
type sessionProbe struct {
	// answered is true when the launcher answered the probe.
	answered       bool
	sessionAuth    string
	fullDiskAccess string
}

// sessionLauncher starts the devices' terminal sessions; nil is the launcher
// socket. Tests replace it.
var sessionLauncher session.Launcher

// launcherProbeTimeout bounds the start-time probe.
const launcherProbeTimeout = 5 * time.Second

// probeLauncher asks the session launcher what it offers. A launcher that
// does not answer is logged and reported as unknown; sessions then refuse
// before their ticket is spent.
func probeLauncher(ctx context.Context, logEvent func(string)) sessionProbe {
	ctx, cancel := context.WithTimeout(ctx, launcherProbeTimeout)
	defer cancel()
	p, err := probe(ctx)
	if err != nil {
		logEvent(fmt.Sprintf("session: the session launcher did not answer its probe: %v", err))
		return sessionProbe{}
	}
	// session_auth describes the PAM path only; Windows logs on through LSA
	// and leaves it unset.
	if runtime.GOOS == "windows" {
		return sessionProbe{answered: true}
	}
	out := sessionProbe{sessionAuth: "no_pam", answered: true}
	if p.PAM {
		out.sessionAuth = "pam"
	}
	if runtime.GOOS == "darwin" {
		out.fullDiskAccess = p.FullDiskAccess
	}
	return out
}

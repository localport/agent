package ui

import (
	"os"
	"strings"
)

// Mode selects which renderer the CLI hands to the agent.
type Mode int

const (
	ModeTUI Mode = iota
	ModePlain
)

func (m Mode) String() string {
	if m == ModeTUI {
		return "tui"
	}
	return "plain"
}

// DetectMode picks a renderer from the --noui flag and the environment.
// Plain mode wins when --noui is set, when stdout/stderr is not a TTY
// (pipes, CI, journald), or when TERM=dumb. Otherwise TUI.
// NO_COLOR does not switch off the TUI. The TUI still draws its layout and
// just drops the ANSI color codes when NO_COLOR is set.
func DetectMode(noUI bool, out *os.File) Mode {
	if noUI || !IsTTY(out) {
		return ModePlain
	}
	if strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return ModePlain
	}
	return ModeTUI
}

// NoColor reports whether the user disabled ANSI colors via NO_COLOR.
func NoColor() bool {
	_, ok := os.LookupEnv("NO_COLOR")
	return ok
}

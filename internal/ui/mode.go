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

// DetectMode picks the renderer. Plain mode is used with --noui, when stdout
// or stderr is not a TTY, or when TERM=dumb. Otherwise the TUI is used.
// NO_COLOR removes colors but keeps the TUI.
func DetectMode(noUI bool, out *os.File) Mode {
	if noUI || !IsTTY(out) {
		return ModePlain
	}
	if strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return ModePlain
	}
	return ModeTUI
}

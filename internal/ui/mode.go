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

// DetectMode picks a renderer from the --ui flag and the environment.
//
// flag may be "auto" (or empty), "tui", or "plain". For "auto" we choose
// the TUI when stdout/stderr is a real terminal and TERM is not "dumb".
// NO_COLOR is not a forcing function here; the TUI honors it by skipping
// ANSI color codes but keeps the layout.
func DetectMode(flag string, out *os.File) Mode {
	switch strings.ToLower(strings.TrimSpace(flag)) {
	case "tui":
		return ModeTUI
	case "plain":
		return ModePlain
	}
	if !IsTTY(out) {
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

package ui

import (
	"fmt"
	"os"
	"strings"
)

// Color palette mirrored from the web dashboard's dark-theme tokens
// (web/src/routes/layout.css). OKLCH values were resolved to sRGB so we
// can drive truecolor terminals exactly; 256-color terminals get the
// nearest xterm code. Brand identity: warm-dark surface, JetBrains-Mono
// green accent.
//
// Use the Sty* functions, not raw ANSI strings. Each function honors
// NO_COLOR (returns the bare string) and the detected color mode.
type rgb struct{ r, g, b uint8 }

type swatch struct {
	rgb     rgb
	x256    uint8  // 256-color (xterm) approximation
	ansi16  string // 16-color fallback ANSI escape
	cssName string // for grep-ability against layout.css
}

var (
	// Resolved from layout.css `.dark`:
	colForeground    = swatch{rgb{0xeb, 0xe6, 0xd4}, 230, "\x1b[97m", "--foreground"}
	colForegroundMid = swatch{rgb{0xc8, 0xc0, 0xad}, 187, "\x1b[37m", "--foreground-mid"}
	colForegroundDim = swatch{rgb{0xad, 0x9f, 0x80}, 144, "\x1b[37m", "--foreground-dim"}
	colMuted         = swatch{rgb{0x6e, 0x67, 0x59}, 244, "\x1b[2;37m", "--muted-foreground"}
	// Border uses a brighter chrome value than --border so the frame
	// stays visible against the warm-dark surface without dominating.
	// Sits between web's --muted-foreground and --foreground-dim.
	colBorder         = swatch{rgb{0x80, 0x77, 0x65}, 242, "\x1b[37m", "--chrome"}
	colPrimary        = swatch{rgb{0x5f, 0xb8, 0x6a}, 78, "\x1b[1;32m", "--primary"}
	colPrimaryMid     = swatch{rgb{0x3a, 0x7a, 0x44}, 65, "\x1b[32m", "--primary-mid"}
	colPrimaryLine    = swatch{rgb{0x29, 0x4e, 0x30}, 22, "\x1b[2;32m", "--primary-line"}
	colWarning        = swatch{rgb{0xd5, 0xa4, 0x4b}, 179, "\x1b[33m", "--warning"}
	colDestructive    = swatch{rgb{0xd3, 0x50, 0x2d}, 167, "\x1b[31m", "--destructive"}
	colDestructiveDim = swatch{rgb{0x6a, 0x28, 0x16}, 88, "\x1b[2;31m", "--destructive-line"}
)

// ColorMode classifies what the terminal can render.
type ColorMode int

const (
	ColorOff       ColorMode = iota // NO_COLOR or non-tty
	Color16                         // 16-color fallback
	Color256                        // xterm 256
	ColorTruecolor                  // 24-bit
)

// DetectColorMode resolves the rendering capability once at startup.
//
// Priority:
//  1. NO_COLOR  → off (https://no-color.org)
//  2. COLORTERM in {truecolor, 24bit} → truecolor
//  3. TERM contains "256color"        → 256
//  4. anything else                   → 16
func DetectColorMode() ColorMode {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return ColorOff
	}
	ct := strings.ToLower(os.Getenv("COLORTERM"))
	if ct == "truecolor" || ct == "24bit" {
		return ColorTruecolor
	}
	term := strings.ToLower(os.Getenv("TERM"))
	if strings.Contains(term, "256color") {
		return Color256
	}
	if term == "" || term == "dumb" {
		return ColorOff
	}
	return Color16
}

// reset and modifiers (kept here so callers don't reach into term.go).
const (
	sgrReset = "\x1b[0m"
	sgrBold  = "\x1b[1m"
	sgrDim   = "\x1b[2m"
)

// fg returns the SGR prefix that paints subsequent text in the swatch's
// foreground color, scaled to the current mode. Empty string when off.
func (s swatch) fg(m ColorMode) string {
	switch m {
	case ColorTruecolor:
		return fmt.Sprintf("\x1b[38;2;%d;%d;%dm", s.rgb.r, s.rgb.g, s.rgb.b)
	case Color256:
		return fmt.Sprintf("\x1b[38;5;%dm", s.x256)
	case Color16:
		return s.ansi16
	}
	return ""
}

// paint wraps text in the swatch color + reset, honoring the mode.
func (s swatch) paint(text string, m ColorMode) string {
	if m == ColorOff || text == "" {
		return text
	}
	return s.fg(m) + text + sgrReset
}

// StyleFn is a curried colorizer bound to a single swatch. The TUI/Plain
// renderers build a struct of these at startup to keep render calls free
// of mode-checking.
type StyleFn func(string) string

// Palette holds the bound colorizers for one ColorMode.
type Palette struct {
	Foreground     StyleFn
	ForegroundMid  StyleFn
	ForegroundDim  StyleFn
	Muted          StyleFn
	Border         StyleFn
	Primary        StyleFn
	PrimaryBold    StyleFn
	PrimaryMid     StyleFn
	PrimaryLine    StyleFn
	Warning        StyleFn
	Destructive    StyleFn
	DestructiveDim StyleFn
	Bold           StyleFn
	Dim            StyleFn
}

// NewPalette binds every swatch to the given mode. Cheap — call once.
func NewPalette(m ColorMode) Palette {
	bind := func(s swatch) StyleFn {
		if m == ColorOff {
			return identity
		}
		prefix := s.fg(m)
		return func(text string) string {
			if text == "" {
				return text
			}
			return prefix + text + sgrReset
		}
	}
	modifier := func(seq string) StyleFn {
		if m == ColorOff {
			return identity
		}
		return func(text string) string {
			if text == "" {
				return text
			}
			return seq + text + sgrReset
		}
	}
	primaryBold := identity
	if m != ColorOff {
		prefix := colPrimary.fg(m) + sgrBold
		primaryBold = func(text string) string {
			if text == "" {
				return text
			}
			return prefix + text + sgrReset
		}
	}
	return Palette{
		Foreground:     bind(colForeground),
		ForegroundMid:  bind(colForegroundMid),
		ForegroundDim:  bind(colForegroundDim),
		Muted:          bind(colMuted),
		Border:         bind(colBorder),
		Primary:        bind(colPrimary),
		PrimaryBold:    primaryBold,
		PrimaryMid:     bind(colPrimaryMid),
		PrimaryLine:    bind(colPrimaryLine),
		Warning:        bind(colWarning),
		Destructive:    bind(colDestructive),
		DestructiveDim: bind(colDestructiveDim),
		Bold:           modifier(sgrBold),
		Dim:            modifier(sgrDim),
	}
}

func identity(s string) string { return s }

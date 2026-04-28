package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/localport/agent/internal/tunnel"
)

// snap is an immutable, lock-free view of TUI state used while rendering.
// Built once per frame under TUI.mu, then handed to buildFrame.
type snap struct {
	cols, rows int
	title      string
	clock      string
	uptime     time.Duration
	edge       string
	tunnels    []tState
	events     []event
	noColor    bool
}

type event struct {
	at    time.Time
	kind  eventKind
	label string
	text  string
}

type eventKind uint8

const (
	evInfo eventKind = iota
	evOK
	evWarn
	evErr
)

// buildFrame returns exactly s.rows lines. Line N is rendered at row N+1.
//
// Single-tunnel layout:
//
//	row 1            ┌ localport ───── 13:44:57 ┐
//	rows 2..N+1      │ <header content>          │
//	row N+2          ├─ events ─────────────────┤
//	rows N+3..rows-1 │ <event rows>              │
//	row rows         └──────────────────────────┘
//
// Multi-tunnel skips the divider and event rows: the box wraps a stat table instead.
func buildFrame(s snap) []string {
	frame := make([]string, s.rows)
	frame[0] = boxTop(s.title, s.clock, s.cols, s.noColor)
	frame[s.rows-1] = boxBottom(s.cols)

	if len(s.tunnels) > 1 {
		fillMulti(frame, s)
	} else {
		fillSingle(frame, s)
	}
	return frame
}

func fillSingle(frame []string, s snap) {
	headerLines := headerSingle(s)

	// Reserve: top(1) + header(N) + divider(1) + events(>=1) + bottom(1).
	maxHeader := max(s.rows-4, 1)
	if len(headerLines) > maxHeader {
		headerLines = headerLines[:maxHeader]
	}
	for i, line := range headerLines {
		frame[1+i] = boxLine(line, s.cols)
	}

	divRow := 1 + len(headerLines)
	frame[divRow] = boxDivider("events", s.cols, s.noColor)

	top := divRow + 1
	bot := s.rows - 2
	capacity := max(bot-top+1, 0)

	visible := s.events
	if len(visible) > capacity {
		visible = visible[len(visible)-capacity:]
	}

	innerW := max(s.cols-4, 0)
	for i := range capacity {
		var content string
		if i < len(visible) {
			content = renderEvent(visible[i], innerW, false, s.noColor)
		}
		frame[top+i] = boxLine(content, s.cols)
	}
}

func fillMulti(frame []string, s snap) {
	headerLines := headerMulti(s)

	maxHeader := s.rows - 2
	if len(headerLines) > maxHeader {
		headerLines = headerLines[:maxHeader]
	}
	for i, line := range headerLines {
		frame[1+i] = boxLine(line, s.cols)
	}
	for i := 1 + len(headerLines); i < s.rows-1; i++ {
		frame[i] = boxLine("", s.cols)
	}
}

func headerSingle(s snap) []string {
	if len(s.tunnels) == 0 {
		return []string{colorize("waiting for config…", SGRDim, s.noColor)}
	}
	ts := s.tunnels[0]
	pill := stateGlyph(ts.state, ts.connected)

	lines := []string{
		fmt.Sprintf("%s   uptime %s   reqs %d   open %d",
			colorize(pill.text, pill.color, s.noColor),
			s.uptime, ts.reqs, ts.openConns),
	}
	if ts.url != "" {
		lines = append(lines, colorize(ts.url, FgCyan+SGRBold, s.noColor))
	}
	lines = append(lines, fmt.Sprintf("%s  →  %s", protoTarget(&ts), ts.local))

	io := fmt.Sprintf("%s in %s    %s out %s",
		colorize("↓", FgCyan, s.noColor), HumanBytes(ts.bytesIn),
		colorize("↑", FgMagenta, s.noColor), HumanBytes(ts.bytesOut))
	if ts.mtls {
		io += "    " + colorize("mTLS", FgGreen+SGRBold, s.noColor)
	}
	lines = append(lines, io)

	if ts.lastErr != "" && ts.state != tunnel.StateActive {
		lines = append(lines, colorize("✕ "+ts.lastErr, FgRed, s.noColor))
	}
	return lines
}

func headerMulti(s snap) []string {
	edgeLine := colorize(
		fmt.Sprintf("edge %s   uptime %s", s.edge, s.uptime),
		SGRDim, s.noColor,
	)

	const stateW = 15
	nameW := 4
	for i := range s.tunnels {
		if n := len(s.tunnels[i].name); n > nameW {
			nameW = n
		}
	}
	nameW++

	urlW := max(s.cols-4-nameW-stateW-6-14-8, 12)

	head := fmt.Sprintf("%-*s  %-*s  %-*s  %5s  %s",
		nameW, "NAME", stateW, "STATE", urlW, "URL/PORT", "REQ", "I/O")
	lines := []string{edgeLine, colorize(head, SGRDim, s.noColor)}

	for i := range s.tunnels {
		ts := s.tunnels[i]
		pill := stateGlyph(ts.state, ts.connected)
		urlOrPort := ts.url
		if urlOrPort == "" {
			urlOrPort = protoTarget(&ts)
		}
		ioStr := HumanBytes(ts.bytesIn) + "/" + HumanBytes(ts.bytesOut)
		lines = append(lines, fmt.Sprintf("%-*s  %s  %-*s  %5d  %s",
			nameW, ts.name,
			colorize(padRight(pill.text, stateW), pill.color, s.noColor),
			urlW, truncate(urlOrPort, urlW),
			ts.reqs, ioStr))
	}
	return lines
}

type styledState struct {
	text  string
	color string
}

func stateGlyph(s tunnel.State, connected bool) styledState {
	if connected && s == tunnel.StateActive {
		return styledState{text: "● connected", color: FgGreen + SGRBold}
	}
	switch s {
	case tunnel.StateConnecting:
		return styledState{text: "◌ connecting", color: FgYellow}
	case tunnel.StateRegistering:
		return styledState{text: "◌ registering", color: FgYellow}
	case tunnel.StateReconnecting:
		return styledState{text: "↻ reconnecting", color: FgYellow}
	case tunnel.StateActive:
		return styledState{text: "● active", color: FgGreen}
	case tunnel.StateStopped:
		return styledState{text: "✕ stopped", color: FgRed}
	}
	return styledState{text: "· idle", color: SGRDim}
}

func protoTarget(ts *tState) string {
	switch {
	case ts.port > 0 && ts.subdomain != "":
		return fmt.Sprintf("%s :%d (%s)", ts.proto, ts.port, ts.subdomain)
	case ts.port > 0:
		return fmt.Sprintf("%s :%d", ts.proto, ts.port)
	case ts.subdomain != "":
		return ts.proto + " " + ts.subdomain
	}
	return ts.proto
}

func renderEvent(e event, maxWidth int, multi, noColor bool) string {
	ts := e.at.Format("15:04:05")
	glyph, color := "·", SGRDim
	switch e.kind {
	case evOK:
		glyph, color = "→", FgGreen
	case evWarn:
		glyph, color = "↻", FgYellow
	case evErr:
		glyph, color = "✕", FgRed
	}
	prefix := colorize(ts, SGRDim, noColor) + "  " + colorize(glyph, color, noColor) + " "
	body := e.text
	if multi && e.label != "" {
		body = colorize("["+e.label+"]", FgCyan, noColor) + " " + body
	}
	full := prefix + body
	if visibleLen(full) > maxWidth {
		full = truncate(stripANSI(full), maxWidth)
	}
	return full
}

// Box drawing.

func boxTop(title, right string, cols int, noColor bool) string {
	if cols < 4 {
		return strings.Repeat("─", cols)
	}
	titleStyled := colorize(title, FgCyan+SGRBold, noColor)
	rightStyled := colorize(right, SGRDim, noColor)

	left := "┌ " + titleStyled + " "
	leftRaw := "┌ " + title + " "
	tail := " " + rightStyled + " ┐"
	tailRaw := " " + right + " ┐"

	fill := cols - visibleLen(leftRaw) - visibleLen(tailRaw)
	if fill < 1 {
		// Title or clock too wide; trim title to fit.
		over := -fill + 1
		title = truncate(title, len(title)-over)
		titleStyled = colorize(title, FgCyan+SGRBold, noColor)
		left = "┌ " + titleStyled + " "
		leftRaw = "┌ " + title + " "
		fill = max(cols-visibleLen(leftRaw)-visibleLen(tailRaw), 1)
	}
	return left + strings.Repeat("─", fill) + tail
}

func boxBottom(cols int) string {
	if cols < 2 {
		return "└┘"
	}
	return "└" + strings.Repeat("─", cols-2) + "┘"
}

func boxDivider(label string, cols int, noColor bool) string {
	if cols < 4 {
		return "├" + strings.Repeat("─", cols-2) + "┤"
	}
	left := "├─ " + colorize(label, SGRDim, noColor) + " "
	leftRaw := "├─ " + label + " "
	right := "─┤"
	fill := max(cols-visibleLen(leftRaw)-visibleLen(right), 1)
	return left + strings.Repeat("─", fill) + right
}

// boxLine wraps content in "│ ... │" with symmetric single-space padding.
// Content is truncated to inner width on overflow; ANSI sequences are
// counted as zero-width via visibleLen.
func boxLine(content string, cols int) string {
	if cols < 2 {
		return "││"
	}
	inner := max(cols-4, 0) // "│ " + content + " │"
	visible := visibleLen(content)
	if visible > inner {
		content = truncate(stripANSI(content), inner)
		visible = visibleLen(content)
	}
	return "│ " + content + strings.Repeat(" ", max(inner-visible, 0)) + " │"
}

// ANSI-aware helpers shared by Plain (none here) and TUI.

func colorize(s, color string, noColor bool) string {
	if noColor || color == "" {
		return s
	}
	return color + s + SGRReset
}

// visibleLen counts visible runes, treating ANSI CSI sequences as zero-width.
// Width is approximated as 1 per rune; double-width glyphs (CJK, most emoji)
// are not handled. Avoid them in framed text.
func visibleLen(s string) int {
	n, inEsc := 0, false
	for _, r := range s {
		if inEsc {
			if isCSITerm(r) {
				inEsc = false
			}
			continue
		}
		if r == 0x1b {
			inEsc = true
			continue
		}
		n++
	}
	return n
}

func stripANSI(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inEsc := false
	for _, r := range s {
		if inEsc {
			if isCSITerm(r) {
				inEsc = false
			}
			continue
		}
		if r == 0x1b {
			inEsc = true
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isCSITerm(r rune) bool {
	switch r {
	case 'm', 'H', 'r', 'K', 'J', 'h', 'l':
		return true
	}
	return false
}

func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n == 1 {
		return string(r[:1])
	}
	return string(r[:n-1]) + "…"
}

func padRight(s string, w int) string {
	if visibleLen(s) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-visibleLen(s))
}

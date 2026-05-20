package ui

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/localport/agent/internal/tunnel"
)

// snap is an immutable, lock-free view of TUI state used while rendering.
// Built once per frame under TUI.mu, then handed to buildFrame.
type snap struct {
	cols, rows int
	title      string
	statusText string // top-right capsule #1, e.g. "Connected" / "Connecting…"
	uptimeText string // top-right capsule #2, e.g. "1m12s"
	edge       string
	tunnels    []tState
	conns      map[string][]tunnel.ActiveConn
	stats      map[string]tunnel.Stats
	spinner    string
	palette    Palette
}

// buildRightCaps composes the two top-right capsules from the tunnels
// snapshot. Single-tunnel: state word + per-tunnel uptime. Multi-tunnel:
// connected/total count + agent uptime.
func buildRightCaps(tunnels []tState, agentUptime time.Duration) (status, uptime string) {
	if len(tunnels) == 0 {
		return "starting…", humanDuration(agentUptime)
	}
	if len(tunnels) == 1 {
		ts := tunnels[0]
		switch {
		case ts.connected && ts.state == tunnel.StateActive:
			return "Connected", humanDuration(time.Since(ts.connectedAt))
		case ts.state == tunnel.StateConnecting:
			return "Connecting…", humanDuration(agentUptime)
		case ts.state == tunnel.StateRegistering:
			return "Registering…", humanDuration(agentUptime)
		case ts.state == tunnel.StateReconnecting:
			return "Reconnecting…", humanDuration(agentUptime)
		case ts.state == tunnel.StateStopped:
			return "Stopped", humanDuration(agentUptime)
		}
		return "Idle", humanDuration(agentUptime)
	}
	connected := 0
	for _, ts := range tunnels {
		if ts.connected && ts.state == tunnel.StateActive {
			connected++
		}
	}
	return fmt.Sprintf("%d/%d connected", connected, len(tunnels)), humanDuration(agentUptime)
}

// buildFrame returns exactly s.rows formatted lines. Line N renders at row N+1.
//
// Layout:
//
//	row 1            ┌─[ localport ]──────[ Connected ][ 1m12s ]─┐
//	rows 2..H+1      │ <header — per-tunnel status card>          │
//	row H+2          ├─[ live connections ]───────────────[ N ]─┤
//	rows H+3..rows-1 │ <connection rows or centered phrase>       │
//	row rows         └────────────────────────────────────────────┘
func buildFrame(s snap) []string {
	frame := make([]string, s.rows)
	pal := s.palette

	frame[0] = boxTop(s.title, s.statusText, s.uptimeText, s.cols, pal)
	frame[s.rows-1] = boxBottom(s.cols, pal)

	header := renderHeader(s)
	maxHeader := max(s.rows-4, 1)
	if len(header) > maxHeader {
		header = header[:maxHeader]
	}
	for i, line := range header {
		frame[1+i] = boxLine(line, s.cols, pal)
	}

	totalConns := 0
	for _, list := range s.conns {
		totalConns += len(list)
	}
	divRow := 1 + len(header)
	frame[divRow] = boxDivider("live connections", fmt.Sprintf("%d", totalConns), s.cols, pal)

	bodyTop := divRow + 1
	bodyBot := s.rows - 2
	capacity := max(bodyBot-bodyTop+1, 0)

	body := renderConnections(s, capacity)
	for i := range capacity {
		var content string
		if i < len(body) {
			content = body[i]
		}
		frame[bodyTop+i] = boxLine(content, s.cols, pal)
	}
	return frame
}

// renderHeader picks between the single-tunnel status card and the
// multi-tunnel table.
func renderHeader(s snap) []string {
	pal := s.palette
	if len(s.tunnels) == 0 {
		return []string{pal.Muted("waiting for config…")}
	}
	if len(s.tunnels) == 1 {
		return headerSingle(s, s.tunnels[0])
	}
	return headerMulti(s)
}

func headerSingle(s snap, ts tState) []string {
	pal := s.palette

	const labelW = 14
	row := func(label, value string) string {
		return pal.ForegroundDim(padRight(label, labelW)) + pal.Foreground(value)
	}

	lines := make([]string, 0, 12)
	lines = append(lines, "") // top padding inside the box

	tname := ts.tunnelName
	if tname == "" {
		tname = ts.name
	}
	if tname != "" {
		lines = append(lines, row("Name", tname))
	}
	if ts.region != "" {
		lines = append(lines, row("Region", strings.ToUpper(ts.region)))
	}

	urls := ts.urls
	if len(urls) == 0 && ts.url != "" {
		urls = []string{ts.url}
	}
	if len(urls) > 0 {
		first := true
		for _, u := range urls {
			leftCol := pal.ForegroundDim(padRight("", labelW))
			if first {
				leftCol = pal.ForegroundDim(padRight("Forwarding", labelW))
				first = false
			}
			lines = append(lines, leftCol+pal.Primary(u))
		}
	}

	local := buildLocalURL(ts.proto, ts.local)
	localLine := pal.ForegroundDim(padRight("Local", labelW)) + pal.Foreground(local)
	if ts.mtls {
		localLine += "   " + pal.Primary("mTLS")
	}
	lines = append(lines, localLine)

	st := s.stats[ts.name]
	bandwidth := pal.ForegroundDim("↓ ") + pal.Foreground(HumanBytes(st.BytesIn)) +
		pal.ForegroundDim("   ↑ ") + pal.Foreground(HumanBytes(st.BytesOut))
	lines = append(lines,
		pal.ForegroundDim(padRight("Bandwidth", labelW))+bandwidth,
		row("Connections", fmt.Sprintf("%d", st.ConnectionsServed)),
	)

	if ts.lastErr != "" && ts.state != tunnel.StateActive {
		inner := max(s.cols-4, 20)
		for i, line := range wrapPlain("✕ "+ts.lastErr, inner) {
			if i == 0 {
				lines = append(lines, pal.Destructive(line))
			} else {
				lines = append(lines, pal.DestructiveDim(line))
			}
		}
	}
	lines = append(lines, "") // bottom padding before the divider
	return lines
}

// buildLocalURL composes the local-side address as a scheme://host:port
// string for display. http/https/tcp/tls all map 1:1 to their scheme.
func buildLocalURL(proto, addr string) string {
	if addr == "" {
		return proto
	}
	switch proto {
	case "http", "https", "tcp", "tls":
		return proto + "://" + addr
	}
	return addr
}

func padRight(s string, w int) string {
	if len(s) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-len(s))
}

func headerMulti(s snap) []string {
	pal := s.palette
	header := pal.ForegroundDim("edge ") + pal.Foreground(s.edge)
	lines := []string{header, ""}

	const stateW = 14
	nameW := 4
	for i := range s.tunnels {
		if n := len(s.tunnels[i].name); n > nameW {
			nameW = n
		}
	}
	nameW++

	urlW := max(s.cols-4-nameW-stateW-4, 12)

	cols := pal.Muted(fmt.Sprintf("%-*s  %-*s  %-*s",
		nameW, "NAME", stateW, "STATE", urlW, "URL/PORT"))
	lines = append(lines, cols)

	for i := range s.tunnels {
		ts := s.tunnels[i]
		pill := statePill(ts, pal)
		urlOrPort := ts.url
		if urlOrPort == "" {
			urlOrPort = protoTarget(&ts)
		}
		row := fmt.Sprintf("%-*s  %s  %s",
			nameW, pal.Foreground(ts.name),
			padVisible(pill, stateW),
			pal.ForegroundMid(truncate(urlOrPort, urlW)),
		)
		lines = append(lines, row)
	}
	return lines
}

// statePill is the colored status chip.
func statePill(ts tState, pal Palette) string {
	if ts.connected && ts.state == tunnel.StateActive {
		return pal.PrimaryBold("● connected")
	}
	switch ts.state {
	case tunnel.StateActive:
		return pal.Primary("● active")
	case tunnel.StateConnecting:
		return pal.Warning("◌ connecting")
	case tunnel.StateRegistering:
		return pal.Warning("◌ registering")
	case tunnel.StateReconnecting:
		return pal.Warning("↻ reconnecting")
	case tunnel.StateStopped:
		return pal.Destructive("✕ stopped")
	}
	return pal.Muted("· idle")
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

// renderConnections lays out the bottom panel — at most `capacity` lines.
func renderConnections(s snap, capacity int) []string {
	if capacity <= 0 {
		return nil
	}
	pal := s.palette

	if len(s.tunnels) == 1 {
		ts := s.tunnels[0]
		conns := s.conns[ts.name]
		if !ts.connected || ts.state != tunnel.StateActive {
			return centeredPanel(connectingPhrase(ts, s.spinner, pal), capacity, s.cols)
		}
		if len(conns) == 0 {
			return centeredPanel(pal.Muted("no live connections"), capacity, s.cols)
		}
		return renderConnTable(conns, capacity, s.cols, pal)
	}

	lines := make([]string, 0, capacity)
	for i, ts := range s.tunnels {
		if i > 0 && len(lines) < capacity {
			lines = append(lines, "")
		}
		if len(lines) >= capacity {
			break
		}
		groupHeader := pal.PrimaryMid("┄ "+ts.name+" ") +
			pal.Muted("· ") + statePill(ts, pal)
		lines = append(lines, groupHeader)
		if len(lines) >= capacity {
			break
		}

		conns := s.conns[ts.name]
		if !ts.connected || ts.state != tunnel.StateActive {
			lines = append(lines, "  "+connectingPhrase(ts, s.spinner, pal))
			continue
		}
		if len(conns) == 0 {
			lines = append(lines, "  "+pal.Muted("no live connections"))
			continue
		}
		groupsLeft := len(s.tunnels) - i - 1
		reserved := groupsLeft * 2
		groupCap := max(capacity-len(lines)-reserved, 1)
		for _, row := range renderConnTable(conns, groupCap, s.cols-2, pal) {
			if len(lines) >= capacity {
				break
			}
			lines = append(lines, "  "+row)
		}
	}
	return lines
}

func connectingPhrase(ts tState, spin string, pal Palette) string {
	switch ts.state {
	case tunnel.StateConnecting:
		return pal.Warning(spin) + " " + pal.ForegroundMid("connecting…")
	case tunnel.StateRegistering:
		return pal.Warning(spin) + " " + pal.ForegroundMid("registering…")
	case tunnel.StateReconnecting:
		return pal.Warning(spin) + " " + pal.ForegroundMid("reconnecting…")
	case tunnel.StateStopped:
		return pal.Destructive("✕ stopped")
	}
	return pal.Muted("· idle")
}

// renderConnTable formats one row per ActiveConn. Sorted by StartedAt
// descending so the newest connection sits on top.
//
//	IP                           DUR     ↓ IN       ↑ OUT
//	203.0.113.4                 3m12s    1.2 MB    430 KB
//
// The remote address is host-only — the source port carries no signal
// for an operator watching the panel, so the port is stripped for clarity.
func renderConnTable(conns []tunnel.ActiveConn, capacity, cols int, pal Palette) []string {
	if capacity <= 0 || len(conns) == 0 {
		return nil
	}
	sorted := append([]tunnel.ActiveConn(nil), conns...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].StartedAt.After(sorted[j].StartedAt)
	})

	innerW := max(cols-4, 20)
	const durW, byteW, gap = 8, 10, 2
	remoteW := max(innerW-durW-byteW*2-gap*3, 12)
	gapStr := strings.Repeat(" ", gap)

	header := padVisible(pal.Muted("IP"), remoteW) + gapStr +
		padVisible(pal.Muted("DUR"), durW) + gapStr +
		padLeftVisible(pal.Muted("↓ IN"), byteW) + gapStr +
		padLeftVisible(pal.Muted("↑ OUT"), byteW)

	rows := make([]string, 0, capacity)
	rows = append(rows, header)

	now := time.Now()
	for _, c := range sorted {
		if len(rows) >= capacity {
			break
		}
		remote := c.Remote
		if remote == "" {
			remote = "—"
		} else if host, _, err := net.SplitHostPort(remote); err == nil && host != "" {
			remote = host
		}
		row := padVisible(pal.Foreground(truncate(remote, remoteW)), remoteW) + gapStr +
			padVisible(pal.Foreground(humanDuration(now.Sub(c.StartedAt))), durW) + gapStr +
			padLeftVisible(pal.Primary(HumanBytes(c.BytesIn)), byteW) + gapStr +
			padLeftVisible(pal.Primary(HumanBytes(c.BytesOut)), byteW)
		rows = append(rows, row)
	}
	if extra := len(sorted) - (capacity - 1); extra > 0 {
		rows[capacity-1] = pal.Muted(fmt.Sprintf("…and %d more", extra))
	}
	return rows
}

// padLeftVisible right-aligns s in a w-wide cell, ignoring ANSI escape
// sequences when measuring width.
func padLeftVisible(s string, w int) string {
	rl := visibleLen(s)
	if rl >= w {
		return s
	}
	return strings.Repeat(" ", w-rl) + s
}

// centeredPanel returns capacity lines with msg vertically and horizontally
// centered. Used for the "Connecting…" / "no live connections" body.
func centeredPanel(msg string, capacity, cols int) []string {
	lines := make([]string, capacity)
	mid := capacity / 2
	inner := max(cols-4, 0)
	pad := max((inner-visibleLen(msg))/2, 0)
	lines[mid] = strings.Repeat(" ", pad) + msg
	return lines
}

// Box drawing.

// boxTop renders:  ┌─[ localport vX ]──[ Connected ][ 1m12s ]─┐
func boxTop(title, status, uptime string, cols int, pal Palette) string {
	if cols < 4 {
		return pal.Border(strings.Repeat("─", cols))
	}
	titleStyled := pal.PrimaryBold(title)
	statusStyled := styleStatusWord(status, pal)
	uptimeStyled := pal.Foreground(uptime)

	leftCapRaw := "┌─[ " + title + " ]"
	rightCapRaw := "[ " + status + " ][ " + uptime + " ]─┐"

	fill := cols - visibleLen(leftCapRaw) - visibleLen(rightCapRaw)
	if fill < 1 {
		over := -fill + 1
		title = truncate(title, max(len(title)-over, 1))
		titleStyled = pal.PrimaryBold(title)
		leftCapRaw = "┌─[ " + title + " ]"
		fill = max(cols-visibleLen(leftCapRaw)-visibleLen(rightCapRaw), 1)
	}
	return pal.Border("┌─[ ") + titleStyled +
		pal.Border(" ]"+strings.Repeat("─", fill)+"[ ") + statusStyled +
		pal.Border(" ][ ") + uptimeStyled + pal.Border(" ]─┐")
}

func styleStatusWord(s string, pal Palette) string {
	switch {
	case strings.HasPrefix(s, "Connected") || strings.HasSuffix(s, "connected"):
		return pal.PrimaryBold(s)
	case strings.HasPrefix(s, "Stopped"):
		return pal.Destructive(s)
	case strings.HasPrefix(s, "Connecting") ||
		strings.HasPrefix(s, "Reconnecting") ||
		strings.HasPrefix(s, "Registering") ||
		strings.HasPrefix(s, "starting"):
		return pal.Warning(s)
	}
	return pal.ForegroundMid(s)
}

func boxBottom(cols int, pal Palette) string {
	if cols < 2 {
		return pal.Border("└┘")
	}
	return pal.Border("└" + strings.Repeat("─", cols-2) + "┘")
}

// boxDivider renders:  ├─[ live connections ]──────[ N ]─┤
func boxDivider(label, right string, cols int, pal Palette) string {
	if cols < 4 {
		return pal.Border("├" + strings.Repeat("─", cols-2) + "┤")
	}
	leftCapRaw := "├─[ " + label + " ]"
	rightCapRaw := "[ " + right + " ]─┤"
	fill := max(cols-visibleLen(leftCapRaw)-visibleLen(rightCapRaw), 1)
	return pal.Border("├─[ ") + pal.ForegroundDim(label) +
		pal.Border(" ]"+strings.Repeat("─", fill)+"[ ") +
		pal.Foreground(right) + pal.Border(" ]─┤")
}

// boxLine wraps content in │ ... │ with symmetric single-space padding.
// Content is truncated to inner width on overflow; ANSI sequences are
// counted as zero-width via visibleLen.
func boxLine(content string, cols int, pal Palette) string {
	if cols < 2 {
		return pal.Border("││")
	}
	inner := max(cols-4, 0)
	visible := visibleLen(content)
	if visible > inner {
		content = truncate(stripANSI(content), inner)
		visible = visibleLen(content)
	}
	pad := max(inner-visible, 0)
	return pal.Border("│") + " " + content + strings.Repeat(" ", pad) + " " + pal.Border("│")
}

// ANSI-aware string helpers.

func visibleLen(s string) int {
	n := 0
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

// wrapPlain word-wraps s to lines no wider than w runes. Tokens longer
// than w are hard-broken. Returns at least one line.
func wrapPlain(s string, w int) []string {
	if w <= 0 {
		return []string{""}
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	var (
		lines []string
		cur   strings.Builder
		curW  int
	)
	flush := func() {
		lines = append(lines, cur.String())
		cur.Reset()
		curW = 0
	}
	for _, word := range words {
		for visibleLen(word) > w {
			runes := []rune(word)
			if curW > 0 {
				flush()
			}
			lines = append(lines, string(runes[:w]))
			word = string(runes[w:])
		}
		add := visibleLen(word)
		if curW == 0 {
			cur.WriteString(word)
			curW = add
			continue
		}
		if curW+1+add > w {
			flush()
			cur.WriteString(word)
			curW = add
			continue
		}
		cur.WriteByte(' ')
		cur.WriteString(word)
		curW += 1 + add
	}
	if curW > 0 {
		flush()
	}
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
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

func padVisible(s string, w int) string {
	rl := visibleLen(s)
	if rl >= w {
		return s
	}
	return s + strings.Repeat(" ", w-rl)
}

// humanDuration prints durations the way ops people read them: 3s, 1m12s,
// 1h04m. Sub-second rounds to seconds for stability between frames.
func humanDuration(d time.Duration) string {
	if d < time.Second {
		return "0s"
	}
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) - m*60
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	h := int(d.Hours())
	m := int(d.Minutes()) - h*60
	return fmt.Sprintf("%dh%02dm", h, m)
}

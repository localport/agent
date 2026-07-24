package ui

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/localport/agent/internal/tunnel"
)

// regionNames maps region slugs to display names; unknown slugs render as
// the uppercased slug.
var regionNames = map[string]string{
	"eu": "EU",
	"us": "US",
	"ap": "Asia Pacific",
}

func regionName(slug string) string {
	if name, ok := regionNames[strings.ToLower(slug)]; ok {
		return name
	}
	return strings.ToUpper(slug)
}

// snap is an immutable, lock-free view of TUI state used while rendering.
// Built once per frame under TUI.mu, then handed to buildFrame.
type snap struct {
	cols, rows int
	title      string
	statusText string // top-right capsule #1, e.g. "Connected" / "Connecting…"
	uptimeText string // top-right capsule #2, e.g. "1m12s"
	errCode    string // bottom-right capsule, opaque edge error code e.g. "AT001"
	edge       string
	tunnels    []tState
	conns      map[string][]tunnel.ActiveConn
	reqs       map[string][]tunnel.RequestInfo
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
//	rows 2..H+1      │ <header: per-tunnel status card>          │
//	row H+2          ├─[ live connections ]───────────────[ N ]─┤
//	rows H+3..rows-1 │ <connection rows or centered phrase>       │
//	row rows         └────────────────────────────────────────────┘
func buildFrame(s snap) []string {
	frame := make([]string, s.rows)
	pal := s.palette

	frame[0] = boxTop(s.title, s.statusText, s.uptimeText, s.cols, pal)
	frame[s.rows-1] = boxBottom(s.cols, s.errCode, pal)

	header := renderHeader(s)
	maxHeader := max(s.rows-4, 1)
	if len(header) > maxHeader {
		header = header[:maxHeader]
	}
	for i, line := range header {
		frame[1+i] = boxLine(line, s.cols, pal)
	}

	divLabel, divCount := panelDivider(s)
	divRow := 1 + len(header)
	frame[divRow] = boxDivider(divLabel, divCount, s.cols, pal)

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
		name := ts.regionName
		if name == "" {
			name = regionName(ts.region)
		}
		lines = append(lines, row("Region", name))
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

// renderConnections lays out the bottom panel, using at most `capacity` lines.
// An http tunnel shows one row per HTTP request; every other protocol shows one
// row per live connection, as before.
func renderConnections(s snap, capacity int) []string {
	if capacity <= 0 {
		return nil
	}
	pal := s.palette

	if len(s.tunnels) == 1 {
		ts := s.tunnels[0]
		if !ts.connected || ts.state != tunnel.StateActive {
			return centeredPanel(connectingPhrase(ts, s.spinner, pal), capacity, s.cols)
		}
		if bottomCount(ts, s) == 0 {
			return centeredPanel(bottomEmptyMsg(ts, pal), capacity, s.cols)
		}
		return bottomRows(ts, s, capacity, s.cols, pal)
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

		if !ts.connected || ts.state != tunnel.StateActive {
			lines = append(lines, "  "+connectingPhrase(ts, s.spinner, pal))
			continue
		}
		if bottomCount(ts, s) == 0 {
			lines = append(lines, "  "+bottomEmptyMsg(ts, pal))
			continue
		}
		groupsLeft := len(s.tunnels) - i - 1
		reserved := groupsLeft * 2
		groupCap := max(capacity-len(lines)-reserved, 1)
		for _, row := range bottomRows(ts, s, groupCap, s.cols-2, pal) {
			if len(lines) >= capacity {
				break
			}
			lines = append(lines, "  "+row)
		}
	}
	return lines
}

// panelDivider labels the bottom panel: requests for a single http tunnel, live
// connections otherwise.
func panelDivider(s snap) (label, count string) {
	if len(s.tunnels) == 1 && httpProto(s.tunnels[0].proto) {
		return "requests", fmt.Sprintf("%d", s.stats[s.tunnels[0].name].RequestsServed)
	}
	total := 0
	for _, list := range s.conns {
		total += len(list)
	}
	return "live connections", fmt.Sprintf("%d", total)
}

func httpProto(proto string) bool { return proto == "http" || proto == "https" }

func bottomCount(ts tState, s snap) int {
	if httpProto(ts.proto) {
		return len(s.reqs[ts.name])
	}
	return len(s.conns[ts.name])
}

func bottomEmptyMsg(ts tState, pal Palette) string {
	if httpProto(ts.proto) {
		return pal.Muted("no requests yet")
	}
	return pal.Muted("no live connections")
}

func bottomRows(ts tState, s snap, capacity, cols int, pal Palette) []string {
	if httpProto(ts.proto) {
		return renderRequestTable(s.reqs[ts.name], capacity, cols, pal)
	}
	return renderConnTable(s.conns[ts.name], capacity, cols, pal)
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
// The remote address is shown host-only. An operator watching the panel gets
// nothing useful from the source port, so it is stripped for clarity.
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
			remote = "-"
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

// renderRequestTable formats one row per HTTP request, newest at the bottom so
// it reads like a log. Shown on http tunnels in place of the connection table.
//
//	TIME      METHOD  PATH                    STATUS   DUR
//	15:04:05  POST    /webhook/slack          200      142ms
//	15:04:06  GET     /health                 200        3ms
func renderRequestTable(reqs []tunnel.RequestInfo, capacity, cols int, pal Palette) []string {
	if capacity <= 0 || len(reqs) == 0 {
		return nil
	}

	innerW := max(cols-4, 20)
	const timeW, methodW, statusW, durW, gap = 8, 7, 6, 8, 2
	pathW := max(innerW-timeW-methodW-statusW-durW-gap*4, 10)
	gapStr := strings.Repeat(" ", gap)

	header := padVisible(pal.Muted("TIME"), timeW) + gapStr +
		padVisible(pal.Muted("METHOD"), methodW) + gapStr +
		padVisible(pal.Muted("PATH"), pathW) + gapStr +
		padVisible(pal.Muted("STATUS"), statusW) + gapStr +
		padLeftVisible(pal.Muted("DUR"), durW)

	rows := make([]string, 0, capacity)
	rows = append(rows, header)

	// The ring is oldest-first; show the most recent that fit, newest last.
	bodyCap := capacity - 1
	start := 0
	if len(reqs) > bodyCap {
		start = len(reqs) - bodyCap
	}
	for _, r := range reqs[start:] {
		row := padVisible(pal.Muted(r.StartedAt.Format("15:04:05")), timeW) + gapStr +
			padVisible(pal.Foreground(padMethod(r.Method, methodW)), methodW) + gapStr +
			padVisible(pal.Foreground(truncate(r.Path, pathW)), pathW) + gapStr +
			padVisible(statusStyle(r.Status, pal)(fmt.Sprintf("%d", r.Status)), statusW) + gapStr +
			padLeftVisible(pal.Foreground(humanLatency(r.Duration)), durW)
		rows = append(rows, row)
	}
	// Mark hidden older requests on the first body row. Skip when only the header
	// fits (capacity 1), else rows[1] is out of range.
	if start > 0 && len(rows) > 1 {
		rows[1] = pal.Muted(fmt.Sprintf("…%d earlier", start))
	}
	return rows
}

// padMethod defends the column against a malformed or oversized method.
func padMethod(m string, w int) string {
	if m == "" {
		return "-"
	}
	return truncate(m, w)
}

// statusStyle colours a status code by class: 2xx primary, 3xx/4xx warning,
// 5xx (and anything unexpected) destructive.
func statusStyle(code int, pal Palette) StyleFn {
	switch {
	case code >= 200 && code < 300:
		return pal.Primary
	case code >= 300 && code < 500:
		return pal.Warning
	default:
		return pal.Destructive
	}
}

// humanLatency shows sub-second timing (µs/ms) that humanDuration collapses to 0s.
func humanLatency(d time.Duration) string {
	switch {
	case d < time.Microsecond:
		return "0µs"
	case d < time.Millisecond:
		return fmt.Sprintf("%dµs", d.Microseconds())
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < 10*time.Second:
		return fmt.Sprintf("%.1fs", d.Seconds())
	default:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
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

func boxBottom(cols int, code string, pal Palette) string {
	if cols < 2 {
		return pal.Border("└┘")
	}
	code = sanitizeForDisplay(code)
	if code == "" {
		return pal.Border("└" + strings.Repeat("─", cols-2) + "┘")
	}
	rightCapRaw := "[ " + code + " ]─┘"
	fill := cols - 1 - visibleLen(rightCapRaw) // 1 = "└"
	if fill < 1 {
		return pal.Border("└" + strings.Repeat("─", cols-2) + "┘")
	}
	return pal.Border("└"+strings.Repeat("─", fill)+"[ ") +
		pal.ForegroundDim(code) + pal.Border(" ]─┘")
}

// sanitizeForDisplay strips terminal control characters (C0 incl. ESC, DEL, and C1)
func sanitizeForDisplay(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == 0x7f || r < 0x20 || (r >= 0x80 && r <= 0x9f) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
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

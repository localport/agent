package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/proto"
	"github.com/localport/agent/internal/tunnel"
)

type TUI struct {
	out     *os.File
	noColor bool

	mu        sync.Mutex
	version   string
	startedAt time.Time
	edge      string
	order     []string
	tunnels   map[string]*tState
	logs      []logLine
	logCap    int

	cols, rows int
	headerRows int

	started    bool
	stopOnce   sync.Once
	stopCh     chan struct{}
	resizeStop func()
}

type tState struct {
	name      string
	proto     string
	local     string
	state     tunnel.State
	url       string
	subdomain string
	port      uint16
	mode      string
	reqs      int64
	openConns int64
	bytesIn   int64
	bytesOut  int64
	lastErr   string
	mtls      bool
	connected bool
}

type logLine struct {
	at    time.Time
	kind  string
	label string
	text  string
}

var _ tunnel.EventHandler = (*TUI)(nil)

func NewTUI() *TUI {
	return &TUI{
		out:       os.Stderr,
		noColor:   NoColor(),
		startedAt: time.Now(),
		tunnels:   make(map[string]*tState),
		logCap:    500,
		stopCh:    make(chan struct{}),
	}
}

// Banner is called once at startup with the parsed config.
func (t *TUI) Banner(version string, cfg *config.Config) {
	t.mu.Lock()
	t.version = version
	for _, s := range cfg.Specs {
		if t.edge == "" {
			t.edge = s.Edge
		}
		for _, ep := range s.Endpoints {
			name := ep.Name
			if name == "" {
				name = "default"
			}
			if _, ok := t.tunnels[name]; !ok {
				t.order = append(t.order, name)
			}
			t.tunnels[name] = &tState{
				name:  name,
				proto: ep.Protocol,
				local: ep.Local,
				state: tunnel.StateIdle,
			}
		}
	}
	t.cols, t.rows = TermSize(t.out)
	t.mu.Unlock()

	t.start()
}

func (t *TUI) start() {
	t.mu.Lock()
	if t.started {
		t.mu.Unlock()
		return
	}
	t.started = true
	t.mu.Unlock()

	fmt.Fprint(t.out, AltScreenOn+CursorHide+ClearScreen)
	t.fullRedraw()

	resizeCh, stop := notifyResize()
	t.resizeStop = stop
	go t.tick()
	go t.handleResize(resizeCh)

	t.appendLog("info", "", "started — Ctrl+C to stop")
}

func (t *TUI) tick() {
	tk := time.NewTicker(time.Second)
	defer tk.Stop()
	for {
		select {
		case <-t.stopCh:
			return
		case <-tk.C:
			t.repaintHeader()
		}
	}
}

func (t *TUI) handleResize(ch <-chan os.Signal) {
	for {
		select {
		case <-t.stopCh:
			return
		case _, ok := <-ch:
			if !ok {
				return
			}
			t.mu.Lock()
			t.cols, t.rows = TermSize(t.out)
			t.mu.Unlock()
			t.fullRedraw()
		}
	}
}

// Shutdown restores the terminal. Safe to call multiple times.
func (t *TUI) Shutdown() {
	t.stopOnce.Do(func() {
		close(t.stopCh)
		if t.resizeStop != nil {
			t.resizeStop()
		}
		fmt.Fprint(t.out, ResetScrollRegion()+MoveTo(t.rows, 1)+CursorShow+AltScreenOff)
	})
}

// EventHandler implementation.

func (t *TUI) OnStateChange(label string, _ tunnel.State, to tunnel.State) {
	t.mu.Lock()
	if ts := t.ensure(label); ts != nil {
		ts.state = to
		if to != tunnel.StateActive {
			ts.connected = false
		}
	}
	t.mu.Unlock()

	switch to {
	case tunnel.StateConnecting:
		t.appendLog("warn", label, "connecting")
	case tunnel.StateRegistering:
		t.appendLog("warn", label, "registering")
	case tunnel.StateReconnecting:
		t.appendLog("warn", label, "reconnecting")
	case tunnel.StateStopped:
		t.appendLog("err", label, "stopped")
	}
	t.repaintHeader()
}

func (t *TUI) OnConnected(label string, info tunnel.Info) {
	endpoint := FirstEndpoint(info.URLs, info.PublicURL, info.EdgeAddr, info.Port)

	t.mu.Lock()
	if ts := t.ensure(label); ts != nil {
		ts.state = tunnel.StateActive
		ts.connected = true
		ts.url = endpoint
		ts.subdomain = info.Subdomain
		ts.port = info.Port
		ts.mode = info.Mode
		ts.lastErr = ""
		if info.MTLS != nil {
			ts.mtls = info.MTLS.Enabled
		}
	}
	if info.EdgeAddr != "" {
		t.edge = info.EdgeAddr
	}
	t.mu.Unlock()

	if endpoint != "" {
		t.appendLog("ok", label, "connected — "+endpoint)
	} else {
		t.appendLog("ok", label, "connected")
	}
	t.repaintHeader()
}

func (t *TUI) OnDisconnected(label string, err error) {
	t.mu.Lock()
	if ts := t.ensure(label); ts != nil {
		ts.connected = false
	}
	t.mu.Unlock()
	if err != nil {
		t.appendLog("warn", label, "disconnected — "+err.Error())
	} else {
		t.appendLog("warn", label, "disconnected")
	}
	t.repaintHeader()
}

func (t *TUI) OnError(label string, err error) {
	t.mu.Lock()
	if ts := t.ensure(label); ts != nil {
		ts.lastErr = err.Error()
	}
	t.mu.Unlock()
	t.appendLog("err", label, err.Error())
	t.repaintHeader()
}

func (t *TUI) OnDataConn(label, _, _ string) {
	t.mu.Lock()
	if ts := t.ensure(label); ts != nil {
		ts.openConns++
		ts.reqs++
	}
	t.mu.Unlock()
	t.repaintHeader()
}

func (t *TUI) OnDataClose(label, connID, local string, bytesIn, bytesOut int64, dur time.Duration, err error) {
	t.mu.Lock()
	if ts := t.ensure(label); ts != nil {
		if ts.openConns > 0 {
			ts.openConns--
		}
		ts.bytesIn += bytesIn
		ts.bytesOut += bytesOut
	}
	t.mu.Unlock()

	short := connID
	if len(short) > 6 {
		short = short[:6]
	}
	if err != nil {
		t.appendLog("err", label, fmt.Sprintf("%s ✕ %s", short, err.Error()))
	} else {
		t.appendLog("ok", label, fmt.Sprintf(
			"%s → %s   ↑%s ↓%s   %s",
			short, local,
			HumanBytes(bytesIn), HumanBytes(bytesOut),
			dur.Round(time.Millisecond),
		))
	}
	t.repaintHeader()
}

func (t *TUI) OnRedirect(label, from, to string) {
	t.mu.Lock()
	t.edge = to
	t.mu.Unlock()
	t.appendLog("info", label, "↻ redirect "+from+" → "+to)
	t.repaintHeader()
}

func (t *TUI) OnShutdownPolicy(label string, code string, lt proto.LimitType, _ bool) {
	parts := []string{"limit reached"}
	if code != "" {
		parts = append(parts, "code="+code)
	}
	if lt != "" {
		parts = append(parts, "type="+string(lt))
	}
	t.appendLog("err", label, strings.Join(parts, " "))
	if hint := PolicyHint(lt); hint != "" {
		t.appendLog("info", label, hint)
	}
	t.repaintHeader()
}

// Internal rendering.

func (t *TUI) ensure(label string) *tState {
	if label == "" {
		label = "default"
	}
	ts, ok := t.tunnels[label]
	if !ok {
		ts = &tState{name: label, state: tunnel.StateIdle}
		t.tunnels[label] = ts
		t.order = append(t.order, label)
	}
	return ts
}

func (t *TUI) appendLog(kind, label, text string) {
	t.mu.Lock()
	t.logs = append(t.logs, logLine{at: time.Now(), kind: kind, label: label, text: text})
	if len(t.logs) > t.logCap {
		t.logs = t.logs[len(t.logs)-t.logCap:]
	}
	cols := t.cols
	rows := t.rows
	headerRows := t.headerRows
	noColor := t.noColor
	line := t.logs[len(t.logs)-1]
	multi := len(t.tunnels) > 1
	t.mu.Unlock()

	if cols == 0 || rows == 0 || headerRows == 0 {
		return
	}
	rendered := t.renderLog(line, cols, multi, noColor)
	// Bottom of scroll region, clear that row, write line; newline scrolls.
	fmt.Fprint(t.out, MoveTo(rows, 1)+ClearLine+rendered+"\n")
}

func (t *TUI) fullRedraw() {
	t.mu.Lock()
	cols, rows := t.cols, t.rows
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}
	t.cols, t.rows = cols, rows

	header := t.buildHeader(cols)
	t.headerRows = len(header)
	headerRows := t.headerRows
	noColor := t.noColor
	logsCopy := append([]logLine(nil), t.logs...)
	multi := len(t.tunnels) > 1
	t.mu.Unlock()

	var b strings.Builder
	b.WriteString(ClearScreen)
	b.WriteString(MoveTo(1, 1))
	for _, line := range header {
		b.WriteString(ClearLine)
		b.WriteString(line)
		b.WriteByte('\n')
	}

	logTop := min(headerRows+1, rows)
	b.WriteString(SetScrollRegion(logTop, rows))

	maxLog := max(rows-headerRows, 0)
	start := 0
	if len(logsCopy) > maxLog {
		start = len(logsCopy) - maxLog
	}
	for i := logTop; i <= rows; i++ {
		b.WriteString(MoveTo(i, 1))
		b.WriteString(ClearLine)
	}
	row := logTop
	for i := start; i < len(logsCopy); i++ {
		b.WriteString(MoveTo(row, 1))
		b.WriteString(t.renderLog(logsCopy[i], cols, multi, noColor))
		row++
	}
	b.WriteString(MoveTo(rows, 1))

	fmt.Fprint(t.out, b.String())
}

func (t *TUI) repaintHeader() {
	t.mu.Lock()
	cols, rows := t.cols, t.rows
	if cols == 0 || rows == 0 {
		t.mu.Unlock()
		return
	}
	header := t.buildHeader(cols)
	prev := t.headerRows
	t.headerRows = len(header)
	headerRows := t.headerRows
	t.mu.Unlock()

	// If the header row count changed, the scroll region needs resetting.
	if prev != headerRows {
		t.fullRedraw()
		return
	}

	var b strings.Builder
	b.WriteString(SaveCursor)
	for i, line := range header {
		b.WriteString(MoveTo(i+1, 1))
		b.WriteString(ClearLine)
		b.WriteString(line)
	}
	b.WriteString(RestoreCursor)
	fmt.Fprint(t.out, b.String())
}

// buildHeader is called under t.mu.
func (t *TUI) buildHeader(cols int) []string {
	uptime := time.Since(t.startedAt).Round(time.Second)
	now := time.Now().Format("15:04:05")

	title := "localport"
	if t.version != "" && t.version != "dev" {
		title += " " + t.version
	}

	var lines []string
	if len(t.tunnels) <= 1 {
		var ts *tState
		if len(t.order) > 0 {
			ts = t.tunnels[t.order[0]]
		}
		lines = append(lines, t.boxTop(title, now, cols))

		if ts == nil {
			lines = append(lines, t.boxLine("waiting for config...", cols))
		} else {
			state := stateGlyph(ts.state, ts.connected)
			head := fmt.Sprintf("%s   uptime %s   reqs %d   open %d",
				colorize(state.text, state.color, t.noColor),
				uptime, ts.reqs, ts.openConns)
			lines = append(lines, t.boxLine(head, cols))

			if ts.url != "" {
				lines = append(lines, t.boxLine(colorize(ts.url, FgCyan+SGRBold, t.noColor), cols))
			}
			lines = append(lines, t.boxLine(fmt.Sprintf("%s  →  %s", protoTarget(ts), ts.local), cols))

			io := fmt.Sprintf("in %s   out %s", HumanBytes(ts.bytesIn), HumanBytes(ts.bytesOut))
			if ts.mtls {
				io += "   " + colorize("🔒 mTLS", FgGreen, t.noColor)
			}
			lines = append(lines, t.boxLine(io, cols))

			if ts.lastErr != "" && ts.state != tunnel.StateActive {
				lines = append(lines, t.boxLine(colorize("✕ "+ts.lastErr, FgRed, t.noColor), cols))
			}
		}
	} else {
		lines = append(lines, t.boxTop(title, now, cols))
		lines = append(lines, t.boxLine(colorize(fmt.Sprintf("edge %s   uptime %s", t.edge, uptime), SGRDim, t.noColor), cols))

		const stateW = 15
		nameW := 4
		for _, name := range t.order {
			if len(name) > nameW {
				nameW = len(name)
			}
		}
		nameW++
		urlW := cols - 4 /*box*/ - nameW - stateW - 6 /*req*/ - 14 /*io*/ - 8 /*spaces*/
		urlW = max(urlW, 12)

		head := fmt.Sprintf("%-*s  %-*s  %-*s  %5s  %s",
			nameW, "NAME", stateW, "STATE", urlW, "URL/PORT", "REQ", "I/O")
		lines = append(lines, t.boxLine(colorize(head, SGRDim, t.noColor), cols))

		for _, name := range t.order {
			ts := t.tunnels[name]
			if ts == nil {
				continue
			}
			st := stateGlyph(ts.state, ts.connected)
			urlOrPort := ts.url
			if urlOrPort == "" {
				urlOrPort = protoTarget(ts)
			}
			ioStr := HumanBytes(ts.bytesIn) + "/" + HumanBytes(ts.bytesOut)
			row := fmt.Sprintf("%-*s  %s  %-*s  %5d  %s",
				nameW, ts.name,
				colorize(padRight(st.text, stateW), st.color, t.noColor),
				urlW, truncate(urlOrPort, urlW),
				ts.reqs, ioStr)
			lines = append(lines, t.boxLine(row, cols))
		}
	}

	lines = append(lines, t.boxBottom("events", cols))
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

// Box drawing.

func (t *TUI) boxTop(title, right string, cols int) string {
	left := "┌ " + colorize(title, SGRBold+FgCyan, t.noColor) + " "
	leftRaw := "┌ " + title + " "
	rightRaw := " " + right + " ┐"
	mid := max(cols-visibleLen(leftRaw)-visibleLen(rightRaw), 1)
	return left + strings.Repeat("─", mid) + " " + colorize(right, SGRDim, t.noColor) + " ┐"
}

func (t *TUI) boxBottom(title string, cols int) string {
	left := "├─ " + colorize(title, SGRDim, t.noColor) + " "
	leftRaw := "├─ " + title + " "
	mid := max(cols-visibleLen(leftRaw)-1, 1)
	return left + strings.Repeat("─", mid) + "┤"
}

func (t *TUI) boxLine(content string, cols int) string {
	inner := max(cols-2, 1)
	visible := visibleLen(content)
	if visible > inner {
		// ANSI-aware truncation is non-trivial; strip and clip.
		content = truncate(stripANSI(content), inner)
		visible = visibleLen(content)
	}
	return "│ " + content + strings.Repeat(" ", max(inner-visible, 0)) + "│"
}

func (t *TUI) renderLog(l logLine, cols int, multi, noColor bool) string {
	ts := l.at.Format("15:04:05")
	glyph, color := "·", SGRDim
	switch l.kind {
	case "ok":
		glyph, color = "→", FgGreen
	case "warn":
		glyph, color = "↻", FgYellow
	case "err":
		glyph, color = "✕", FgRed
	}
	prefix := colorize(ts, SGRDim, noColor) + "  " + colorize(glyph, color, noColor) + " "
	body := l.text
	if multi && l.label != "" {
		body = colorize("["+l.label+"]", FgCyan, noColor) + " " + body
	}
	full := prefix + body
	if visibleLen(full) > cols {
		full = truncate(stripANSI(full), cols)
	}
	return full
}

func colorize(s, color string, noColor bool) string {
	if noColor || color == "" {
		return s
	}
	return color + s + SGRReset
}

// visibleLen counts visible runes, skipping ANSI escape sequences.
func visibleLen(s string) int {
	n, inEsc := 0, false
	for _, r := range s {
		if inEsc {
			if r == 'm' || r == 'H' || r == 'r' || r == 'K' || r == 'J' {
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
	inEsc := false
	for _, r := range s {
		if inEsc {
			if r == 'm' || r == 'H' || r == 'r' || r == 'K' || r == 'J' {
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

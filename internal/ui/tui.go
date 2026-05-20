package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/proto"
	"github.com/localport/agent/internal/tunnel"
)

// TUI renders a single bordered frame: status header on top, live
// connections panel underneath. Pure ANSI, no external deps.
//
// Render policy:
//   - Frame redraws on state-mutating events (push). No tickers — the
//     header only changes shape on state transitions, so a poll loop
//     would just burn CPU.
//   - DECAWM (autowrap) is disabled during writes so a cell at the last
//     column never bleeds into the next row.
//
// Concurrency:
//   - mu guards static tunnel state.
//   - The connection registry lives inside each tunnel.Tunnel; the TUI
//     pulls ActiveConnections() / Stats() at render time and never holds
//     a reference between frames.
type TUI struct {
	out     *os.File
	palette Palette

	mu        sync.Mutex
	version   string
	startedAt time.Time
	edge      string
	order     []string
	tunnels   map[string]*tState
	cols      int
	rows      int

	provider     func() []*tunnel.Tunnel
	spinnerFrame atomic.Uint32

	renderMu   sync.Mutex
	renderCh   chan struct{}
	stopOnce   sync.Once
	stopCh     chan struct{}
	resizeStop func()
	rawRestore func()
	started    bool
}

// tState mirrors the static-ish per-tunnel info populated from
// EventHandler callbacks. Live byte counters and remote IPs come from
// the tunnel's own connection registry at render time.
type tState struct {
	name        string
	tunnelName  string
	region      string
	proto       string
	local       string
	state       tunnel.State
	url         string
	urls        []string
	subdomain   string
	port        uint16
	mode        string
	connectedAt time.Time
	lastErr     string
	mtls        bool
	connected   bool
}

const (
	minCols = 24
	minRows = 8

	wrapOff = "\x1b[?7l"
	wrapOn  = "\x1b[?7h"

	spinnerInterval = 120 * time.Millisecond
)

// Braille spinner frames. 10 frames @ 120ms ≈ 1.2s rotation.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

var _ tunnel.EventHandler = (*TUI)(nil)

func NewTUI() *TUI {
	return &TUI{
		out:       os.Stderr,
		palette:   NewPalette(DetectColorMode()),
		startedAt: time.Now(),
		tunnels:   make(map[string]*tState),
		renderCh:  make(chan struct{}, 1),
		stopCh:    make(chan struct{}),
	}
}

// SetTunnelProvider lets the TUI pull ActiveConnections() and Stats()
// from each running Tunnel at render time. Wire this once after agent.New.
func (t *TUI) SetTunnelProvider(p func() []*tunnel.Tunnel) {
	t.mu.Lock()
	t.provider = p
	t.mu.Unlock()
}

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

	if IsTTY(os.Stdin) {
		if restore, err := enterRaw(os.Stdin); err == nil {
			t.rawRestore = restore
			go t.drainStdin()
		}
	}

	resizeCh, stop := notifyResize()
	t.resizeStop = stop
	go t.renderLoop()
	go t.resizeLoop(resizeCh)
	go t.animationLoop()

	t.requestRender()
}

// animationLoop drives the spinner with one ticker. It only requests a
// render when there is something on screen that changes between frames
func (t *TUI) animationLoop() {
	tk := time.NewTicker(spinnerInterval)
	defer tk.Stop()
	for {
		select {
		case <-t.stopCh:
			return
		case <-tk.C:
			if t.shouldAnimate() {
				t.spinnerFrame.Add(1)
				t.requestRender()
			}
		}
	}
}

func (t *TUI) shouldAnimate() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, ts := range t.tunnels {
		switch ts.state {
		case tunnel.StateConnecting, tunnel.StateRegistering,
			tunnel.StateReconnecting, tunnel.StateActive:
			return true
		}
	}
	return false
}

func (t *TUI) drainStdin() {
	buf := make([]byte, 64)
	for {
		select {
		case <-t.stopCh:
			return
		default:
		}
		if _, err := os.Stdin.Read(buf); err != nil {
			return
		}
	}
}

func (t *TUI) Shutdown() {
	t.stopOnce.Do(func() {
		close(t.stopCh)
		if t.resizeStop != nil {
			t.resizeStop()
		}
		if t.rawRestore != nil {
			t.rawRestore()
		}
		fmt.Fprint(t.out, wrapOn+CursorShow+AltScreenOff)
	})
}

func (t *TUI) requestRender() {
	select {
	case t.renderCh <- struct{}{}:
	default:
	}
}

func (t *TUI) renderLoop() {
	for {
		select {
		case <-t.stopCh:
			return
		case <-t.renderCh:
			t.render()
		}
	}
}

func (t *TUI) resizeLoop(ch <-chan os.Signal) {
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
			t.requestRender()
		}
	}
}

// EventHandler implementation.

func (t *TUI) OnStateChange(label string, _, to tunnel.State) {
	t.mu.Lock()
	if ts := t.ensure(label); ts != nil {
		ts.state = to
		if to != tunnel.StateActive {
			ts.connected = false
		}
	}
	t.mu.Unlock()
	t.requestRender()
}

func (t *TUI) OnConnected(label string, info tunnel.Info) {
	t.mu.Lock()
	if ts := t.ensure(label); ts != nil {
		ts.state = tunnel.StateActive
		ts.connected = true
		ts.connectedAt = time.Now()
		ts.tunnelName = info.TunnelName
		ts.region = info.Region
		ts.url = FirstEndpoint(info.URLs, info.PublicURL, info.EdgeAddr, info.Port)
		ts.urls = append(ts.urls[:0], info.URLs...)
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
	t.requestRender()
}

func (t *TUI) OnDisconnected(label string, _ error) {
	t.mu.Lock()
	if ts := t.ensure(label); ts != nil {
		ts.connected = false
	}
	t.mu.Unlock()
	t.requestRender()
}

func (t *TUI) OnError(label string, err error) {
	t.mu.Lock()
	if ts := t.ensure(label); ts != nil {
		ts.lastErr = err.Error()
	}
	t.mu.Unlock()
	t.requestRender()
}

// OnDataConn / OnDataClose only trigger a redraw — the source of truth
// for the live-connections panel is tunnel.Tunnel.ActiveConnections(),
// polled at render time.
func (t *TUI) OnDataConn(_, _, _, _ string)                                        { t.requestRender() }
func (t *TUI) OnDataClose(_, _, _, _ string, _, _ int64, _ time.Duration, _ error) { t.requestRender() }

func (t *TUI) OnRedirect(_, _, to string) {
	t.mu.Lock()
	t.edge = to
	t.mu.Unlock()
	t.requestRender()
}

func (t *TUI) OnShutdownPolicy(label, code string, lt proto.LimitType, _ bool) {
	parts := []string{"limit reached"}
	if code != "" {
		parts = append(parts, "code="+code)
	}
	if lt != "" {
		parts = append(parts, "type="+string(lt))
	}
	msg := strings.Join(parts, " ")
	if hint := PolicyHint(lt); hint != "" {
		msg += " — " + hint
	}
	t.mu.Lock()
	if ts := t.ensure(label); ts != nil {
		ts.lastErr = msg
	}
	t.mu.Unlock()
	t.requestRender()
}

// Internals.

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

func (t *TUI) snapshot() snap {
	t.mu.Lock()
	defer t.mu.Unlock()

	cols := max(t.cols, minCols)
	rows := max(t.rows, minRows)

	tunnels := make([]tState, 0, len(t.order))
	for _, name := range t.order {
		ts := t.tunnels[name]
		if ts == nil {
			continue
		}
		tunnels = append(tunnels, *ts)
	}

	conns := make(map[string][]tunnel.ActiveConn, len(tunnels))
	stats := make(map[string]tunnel.Stats, len(tunnels))
	if t.provider != nil {
		for _, tun := range t.provider() {
			label := tun.Label()
			conns[label] = tun.ActiveConnections()
			stats[label] = tun.Stats()
		}
	}

	title := "localport"
	if t.version != "" && t.version != "dev" {
		v := t.version
		if i := strings.IndexAny(v, "-"); i > 0 {
			v = v[:i]
		}
		if !strings.HasPrefix(v, "v") {
			v = "v" + v
		}
		title = "localport " + v
	}

	status, uptime := buildRightCaps(tunnels, time.Since(t.startedAt))
	return snap{
		cols:       cols,
		rows:       rows,
		title:      title,
		statusText: status,
		uptimeText: uptime,
		edge:       t.edge,
		tunnels:    tunnels,
		conns:      conns,
		stats:      stats,
		spinner:    spinnerFrames[t.spinnerFrame.Load()%uint32(len(spinnerFrames))],
		palette:    t.palette,
	}
}

func (t *TUI) render() {
	t.renderMu.Lock()
	defer t.renderMu.Unlock()

	s := t.snapshot()
	frame := buildFrame(s)

	var b strings.Builder
	b.Grow(s.rows * (s.cols + 16))
	b.WriteString(wrapOff)
	for i, line := range frame {
		b.WriteString(MoveTo(i+1, 1))
		b.WriteString(ClearLine)
		b.WriteString(line)
	}
	b.WriteString(MoveTo(s.rows, 1))
	b.WriteString(wrapOn)

	fmt.Fprint(t.out, b.String())
}

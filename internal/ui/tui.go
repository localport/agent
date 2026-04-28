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

// TUI renders a single bordered frame: header card on top, event log
// below, divider between. Pure ANSI, no external TUI dependency.
//
// Render policy:
//   - Redraw on state-mutating events and on terminal resize. No tickers,
//     no scroll regions. Older events fall off once the window fills up.
//   - Autowrap (DECAWM) is disabled during writes so writing into the
//     last column never spills onto the next row.
//
// Concurrency:
//   - mu guards application state.
//   - A single render goroutine drains a 1-cap signal channel; bursts of
//     events coalesce into one frame.
type TUI struct {
	out     *os.File
	noColor bool

	mu        sync.Mutex
	version   string
	startedAt time.Time
	edge      string
	order     []string
	tunnels   map[string]*tState
	events    []event
	cols      int
	rows      int

	renderMu   sync.Mutex
	renderCh   chan struct{}
	stopOnce   sync.Once
	stopCh     chan struct{}
	resizeStop func()
	rawRestore func()
	started    bool
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

const (
	eventBufCap = 256
	minCols     = 24
	minRows     = 6

	wrapOff = "\x1b[?7l"
	wrapOn  = "\x1b[?7h"
)

var _ tunnel.EventHandler = (*TUI)(nil)

func NewTUI() *TUI {
	return &TUI{
		out:       os.Stderr,
		noColor:   NoColor(),
		startedAt: time.Now(),
		tunnels:   make(map[string]*tState),
		events:    make([]event, 0, eventBufCap),
		renderCh:  make(chan struct{}, 1),
		stopCh:    make(chan struct{}),
	}
}

// Banner ingests static config then enters the alt-screen.
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

	t.requestRender()
}

// drainStdin discards any bytes the user types or that the terminal emits
// for mouse-wheel scrolls (CSI sequences) so they never appear in the
// rendered frame. ICANON is off (see enterRaw) so reads return per byte.
// The goroutine exits when the process exits; Shutdown restores termios
// first so subsequent input goes back to the shell.
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

// Shutdown restores the terminal. Safe to call multiple times.
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
		t.appendEvent(evWarn, label, "connecting")
	case tunnel.StateRegistering:
		t.appendEvent(evWarn, label, "registering")
	case tunnel.StateReconnecting:
		t.appendEvent(evWarn, label, "reconnecting")
	case tunnel.StateStopped:
		t.appendEvent(evErr, label, "stopped")
	}
	t.requestRender()
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
		t.appendEvent(evOK, label, "connected — "+endpoint)
	} else {
		t.appendEvent(evOK, label, "connected")
	}
	t.requestRender()
}

func (t *TUI) OnDisconnected(label string, err error) {
	t.mu.Lock()
	if ts := t.ensure(label); ts != nil {
		ts.connected = false
	}
	t.mu.Unlock()
	if err != nil {
		t.appendEvent(evWarn, label, "disconnected — "+err.Error())
	} else {
		t.appendEvent(evWarn, label, "disconnected")
	}
	t.requestRender()
}

func (t *TUI) OnError(label string, err error) {
	t.mu.Lock()
	if ts := t.ensure(label); ts != nil {
		ts.lastErr = err.Error()
	}
	t.mu.Unlock()
	t.appendEvent(evErr, label, err.Error())
	t.requestRender()
}

func (t *TUI) OnDataConn(label, _, _ string) {
	t.mu.Lock()
	if ts := t.ensure(label); ts != nil {
		ts.openConns++
		ts.reqs++
	}
	t.mu.Unlock()
	t.requestRender()
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
		t.appendEvent(evErr, label, fmt.Sprintf("%s ✕ %s", short, err.Error()))
	} else {
		t.appendEvent(evOK, label, fmt.Sprintf(
			"%s → %s   ↑%s ↓%s   %s",
			short, local,
			HumanBytes(bytesIn), HumanBytes(bytesOut),
			dur.Round(time.Millisecond),
		))
	}
	t.requestRender()
}

func (t *TUI) OnRedirect(label, from, to string) {
	t.mu.Lock()
	t.edge = to
	t.mu.Unlock()
	t.appendEvent(evInfo, label, "↻ redirect "+from+" → "+to)
	t.requestRender()
}

func (t *TUI) OnShutdownPolicy(label string, code string, lt proto.LimitType, _ bool) {
	parts := []string{"limit reached"}
	if code != "" {
		parts = append(parts, "code="+code)
	}
	if lt != "" {
		parts = append(parts, "type="+string(lt))
	}
	t.appendEvent(evErr, label, strings.Join(parts, " "))
	if hint := PolicyHint(lt); hint != "" {
		t.appendEvent(evInfo, label, hint)
	}
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

func (t *TUI) appendEvent(kind eventKind, label, text string) {
	t.mu.Lock()
	t.events = append(t.events, event{at: time.Now(), kind: kind, label: label, text: text})
	if len(t.events) > eventBufCap {
		copy(t.events, t.events[len(t.events)-eventBufCap:])
		t.events = t.events[:eventBufCap]
	}
	t.mu.Unlock()
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
	events := append([]event(nil), t.events...)

	title := "localport"
	if t.version != "" && t.version != "dev" {
		title = "localport " + t.version
	}

	return snap{
		cols:    cols,
		rows:    rows,
		title:   title,
		clock:   time.Now().Format("15:04:05"),
		uptime:  time.Since(t.startedAt).Round(time.Second),
		edge:    t.edge,
		tunnels: tunnels,
		events:  events,
		noColor: t.noColor,
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

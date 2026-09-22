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

// TUI renders one bordered frame with a status header and a connections panel
// below, using ANSI sequences only.
//
// Frames redraw on state events and on the animationLoop timer. Autowrap
// (DECAWM) is off during writes so the last column does not wrap.
//
// mu guards per-tunnel state. Live connections are read from each
// tunnel.Tunnel at render time and not kept between frames.
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

// tState holds per-tunnel state from EventHandler callbacks. Live counters and
// remote addresses are read from the tunnel at render time.
type tState struct {
	name        string
	tunnelName  string
	region      string
	regionName  string
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
	lastCode    string
	mtls        bool
	connected   bool

	// device marks a fleet device. ports are the open ports and local is the
	// target host.
	device bool
	ports  []proto.DevicePort

	// events is a device's log of connection and request rows, newest last.
	// openConns keeps each open connection's port and consumer for its close
	// row.
	events    []devEvent
	openConns map[string]devEvent
}

type devEventKind int

const (
	devConnOpen devEventKind = iota
	devConnClose
	devRequest
)

// devEvent is one row of a device's connection log.
type devEvent struct {
	at       time.Time
	kind     devEventKind
	port     uint16
	remote   string
	consumer string
	method   string
	path     string
	status   int
	dur      time.Duration
	bytes    int64
	err      string
}

// maxDeviceEvents bounds the log's memory.
const maxDeviceEvents = 200

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
	add := func(name, protocol, local string, device bool) {
		if name == "" {
			name = "default"
		}
		if _, ok := t.tunnels[name]; !ok {
			t.order = append(t.order, name)
		}
		t.tunnels[name] = &tState{
			name:   name,
			proto:  protocol,
			local:  local,
			device: device,
			state:  tunnel.StateIdle,
		}
	}
	for _, spec := range cfg.Tunnels {
		if t.edge == "" {
			t.edge = spec.Edge
		}
		add(spec.Name, spec.Protocol, spec.Local, false)
	}
	for _, device := range cfg.Devices {
		if t.edge == "" {
			t.edge = device.Edge
		}
		add(device.Name, "", device.Host, true)
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

	// Set the teardown hooks under the lock. Shutdown reads them from the
	// signal goroutine.
	if IsTTY(os.Stdin) {
		if restore, err := enterRaw(os.Stdin); err == nil {
			t.mu.Lock()
			t.rawRestore = restore
			t.mu.Unlock()
			go t.drainStdin()
		}
	}

	resizeCh, stop := notifyResize()
	t.mu.Lock()
	t.resizeStop = stop
	t.mu.Unlock()
	go t.renderLoop()
	go t.resizeLoop(resizeCh)
	go t.animationLoop()

	t.requestRender()
}

// animationLoop redraws on one timer. It runs at spinner speed while a tunnel
// is transitioning, once per second while connected and only checks otherwise.
func (t *TUI) animationLoop() {
	timer := time.NewTimer(spinnerInterval)
	defer timer.Stop()
	for {
		select {
		case <-t.stopCh:
			return
		case <-timer.C:
		}
		next := time.Second
		switch t.animPace() {
		case paceSpinner:
			t.spinnerFrame.Add(1)
			t.requestRender()
			next = spinnerInterval
		case paceSlow:
			t.requestRender()
		case paceIdle:
			// Nothing changes on screen.
		}
		timer.Reset(next)
	}
}

type animPace int

const (
	paceIdle    animPace = iota // no live tunnels: nothing animates
	paceSlow                    // connected: uptime/counters tick once per second
	paceSpinner                 // transitioning: spinner frames
)

func (t *TUI) animPace() animPace {
	t.mu.Lock()
	defer t.mu.Unlock()
	pace := paceIdle
	for _, ts := range t.tunnels {
		switch ts.state {
		case tunnel.StateConnecting, tunnel.StateRegistering, tunnel.StateReconnecting:
			return paceSpinner
		case tunnel.StateActive:
			pace = paceSlow
		}
	}
	return pace
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
		// Read under the lock and call outside it, since both hooks block on
		// syscalls.
		t.mu.Lock()
		resizeStop, rawRestore := t.resizeStop, t.rawRestore
		t.mu.Unlock()
		if resizeStop != nil {
			resizeStop()
		}
		if rawRestore != nil {
			rawRestore()
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
		ts.regionName = info.RegionName
		ts.url = FirstEndpoint(info.URLs, info.PublicURL, info.EdgeAddr, info.Port)
		ts.urls = append(ts.urls[:0], info.URLs...)
		ts.subdomain = info.Subdomain
		ts.port = info.Port
		ts.mode = info.Mode
		ts.lastErr = ""
		ts.lastCode = ""
		if info.MTLS != nil {
			ts.mtls = info.MTLS.Enabled
		}
		if info.Device {
			ts.device = true
			ts.ports = info.Ports
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
		// The session's connections are gone. Drop entries without a close
		// event.
		clear(ts.openConns)
	}
	t.mu.Unlock()
	t.requestRender()
}

func (t *TUI) OnError(label string, err error) {
	t.mu.Lock()
	if ts := t.ensure(label); ts != nil {
		ts.lastErr = err.Error()
		if code := errorCode(err); code != "" {
			ts.lastCode = code
		}
	}
	t.mu.Unlock()
	t.requestRender()
}

// OnDataConn records device connections in the log so closed ones stay
// visible. Tunnels read live connections at render time.
func (t *TUI) OnDataConn(label string, info tunnel.DataConnInfo) {
	t.mu.Lock()
	if ts := t.ensure(label); ts != nil && ts.device {
		ev := devEvent{
			at:       time.Now(),
			kind:     devConnOpen,
			port:     info.Port,
			remote:   info.Remote,
			consumer: info.Consumer,
		}
		if ts.openConns == nil {
			ts.openConns = make(map[string]devEvent)
		}
		ts.openConns[info.ConnID] = ev
		ts.appendEvent(ev)
	}
	t.mu.Unlock()
	t.requestRender()
}

// OnPortsUpdate replaces a device's port list in the view.
func (t *TUI) OnPortsUpdate(label string, ports []proto.DevicePort) {
	t.mu.Lock()
	if st, ok := t.tunnels[label]; ok {
		st.ports = ports
		st.device = true
	}
	t.mu.Unlock()
	t.requestRender()
}

func (t *TUI) OnDataClose(label, connID, _, remote string, bytesIn, bytesOut int64, dur time.Duration, err error) {
	t.mu.Lock()
	if ts := t.ensure(label); ts != nil && ts.device {
		ev := devEvent{
			at:     time.Now(),
			kind:   devConnClose,
			remote: remote,
			dur:    dur,
			bytes:  bytesIn + bytesOut,
		}
		// Take port and consumer from the open row.
		if opened, ok := ts.openConns[connID]; ok {
			ev.port, ev.consumer = opened.port, opened.consumer
			delete(ts.openConns, connID)
		}
		if err != nil {
			ev.err = err.Error()
		}
		ts.appendEvent(ev)
	}
	t.mu.Unlock()
	t.requestRender()
}

func (t *TUI) OnHTTPRequest(label string, r tunnel.RequestInfo) {
	t.mu.Lock()
	if ts := t.ensure(label); ts != nil && ts.device {
		ts.appendEvent(devEvent{
			at:     r.StartedAt,
			kind:   devRequest,
			port:   r.Port,
			method: r.Method,
			path:   r.Path,
			status: r.Status,
			dur:    r.Duration,
		})
	}
	t.mu.Unlock()
	t.requestRender()
}

// appendEvent adds a row to the ring, newest last. Callers hold t.mu.
func (ts *tState) appendEvent(ev devEvent) {
	if len(ts.events) == maxDeviceEvents {
		copy(ts.events, ts.events[1:])
		ts.events[len(ts.events)-1] = ev
		return
	}
	ts.events = append(ts.events, ev)
}

func (t *TUI) OnRedirect(_, _, to string) {
	t.mu.Lock()
	t.edge = to
	t.mu.Unlock()
	t.requestRender()
}

func (t *TUI) OnShutdownPolicy(label, reason, code string, lt proto.LimitType, _ bool) {
	msg := reason
	if msg == "" {
		msg = PolicyHint(lt)
	}
	if msg == "" {
		msg = "tunnel closed by the server"
	}
	t.mu.Lock()
	if ts := t.ensure(label); ts != nil {
		ts.lastErr = msg
		ts.lastCode = code
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
		copied := *ts
		copied.events = append([]devEvent(nil), ts.events...)
		tunnels = append(tunnels, copied)
	}

	conns := make(map[string][]tunnel.ActiveConn, len(tunnels))
	stats := make(map[string]tunnel.Stats, len(tunnels))
	reqs := make(map[string][]tunnel.RequestInfo, len(tunnels))
	if t.provider != nil {
		for _, tun := range t.provider() {
			label := tun.Label()
			conns[label] = tun.ActiveConnections()
			stats[label] = tun.Stats()
			reqs[label] = tun.RecentRequests()
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

	// The bottom-right capsule shows the last error code while a tunnel is
	// inactive.
	errCode := ""
	for _, ts := range tunnels {
		if ts.lastCode != "" && ts.state != tunnel.StateActive {
			errCode = ts.lastCode
			break
		}
	}

	return snap{
		cols:       cols,
		rows:       rows,
		title:      title,
		statusText: status,
		uptimeText: uptime,
		errCode:    errCode,
		edge:       t.edge,
		tunnels:    tunnels,
		conns:      conns,
		reqs:       reqs,
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

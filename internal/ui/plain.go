package ui

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/proto"
	"github.com/localport/agent/internal/tunnel"
)

const usageReportInterval = 60 * time.Second

// Plain is a line-oriented event handler suitable for non-tty stdouts
// (CI logs, journald, file redirection). No ANSI escapes, no in-place
// updates. Each event becomes one line.
type Plain struct {
	out io.Writer

	mu    sync.Mutex
	stats map[string]*plainStats

	// Usage ticker lifecycle. The goroutine is started lazily on the
	// first data event so single-shot invocations don't spawn it.
	tickerOnce sync.Once
	stopOnce   sync.Once
	stop       chan struct{}
}

type plainStats struct {
	bytesIn, bytesOut int64
	active            int
	totalConns        int64
	dirtySinceTick    bool
}

var _ tunnel.EventHandler = (*Plain)(nil)

func NewPlain() *Plain {
	return &Plain{
		out:   os.Stderr,
		stats: make(map[string]*plainStats),
		stop:  make(chan struct{}),
	}
}

func (p *Plain) Banner(version string, cfg *config.Config) {
	p.line("startup", "", "localport "+version)
	for _, s := range cfg.Specs {
		region := s.Region
		if region == "" {
			region = "auto"
		}
		p.line("startup", "", fmt.Sprintf("region=%s edge=%s", region, s.Edge))
		for _, ep := range s.Endpoints {
			p.line("startup", ep.Name, fmt.Sprintf("proto=%s local=%s", ep.Protocol, ep.Local))
		}
	}
}

func (p *Plain) Shutdown() {
	p.stopOnce.Do(func() { close(p.stop) })
	p.line("shutdown", "", "stopping")
}

func (p *Plain) OnStateChange(label string, _ tunnel.State, to tunnel.State) {
	switch to {
	case tunnel.StateConnecting:
		p.line("state", label, "connecting")
	case tunnel.StateRegistering:
		p.line("state", label, "registering")
	case tunnel.StateReconnecting:
		p.line("state", label, "reconnecting")
	case tunnel.StateStopped:
		p.line("state", label, "stopped")
	}
}

func (p *Plain) OnConnected(label string, info tunnel.Info) {
	endpoint := FirstEndpoint(info.URLs, info.PublicURL, info.EdgeAddr, info.Port)
	p.line("connected", label, endpoint)
	if info.Subdomain != "" || info.Port > 0 {
		sub := info.Subdomain
		if sub == "" {
			sub = "-"
		}
		port := "-"
		if info.Port > 0 {
			port = strconv.Itoa(int(info.Port))
		}
		p.line("connected", label, fmt.Sprintf(
			"subdomain=%s port=%s mode=%s proto=%s",
			sub, port, info.Mode, info.Protocol,
		))
	}
	if info.MTLS != nil && info.MTLS.Enabled {
		p.line("mtls", label, "enabled fp="+info.MTLS.CAFingerprint)
	}
}

func (p *Plain) OnDisconnected(label string, err error) {
	if err != nil {
		p.line("disconnected", label, err.Error())
		return
	}
	p.line("disconnected", label, "")
}

func (p *Plain) OnError(label string, err error) {
	p.line("error", label, err.Error())
}

func (p *Plain) OnDataConn(label, connID, local, remote string) {
	from := remote
	if from == "" {
		from = "-"
	}
	p.line("conn.open", label, fmt.Sprintf("id=%s from=%s -> %s", shortID(connID), from, local))

	p.mu.Lock()
	s := p.statsFor(label)
	s.active++
	s.totalConns++
	s.dirtySinceTick = true
	p.mu.Unlock()

	p.ensureUsageTicker()
}

func (p *Plain) OnDataClose(label, connID, local, remote string, bytesIn, bytesOut int64, dur time.Duration, err error) {
	short := shortID(connID)
	from := remote
	if from == "" {
		from = "-"
	}
	if err != nil {
		p.line("conn.error", label, fmt.Sprintf("id=%s from=%s -> %s: %s", short, from, local, err))
	} else {
		p.line("conn.close", label, fmt.Sprintf(
			"id=%s from=%s -> %s in=%s out=%s dur=%s",
			short, from, local, HumanBytes(bytesIn), HumanBytes(bytesOut), dur.Round(time.Millisecond),
		))
	}

	p.mu.Lock()
	s := p.statsFor(label)
	if s.active > 0 {
		s.active--
	}
	s.bytesIn += bytesIn
	s.bytesOut += bytesOut
	s.dirtySinceTick = true
	p.mu.Unlock()
}

// statsFor returns the per-label stats record, creating it if missing.
// Caller holds p.mu.
func (p *Plain) statsFor(label string) *plainStats {
	if s, ok := p.stats[label]; ok {
		return s
	}
	s := &plainStats{}
	p.stats[label] = s
	return s
}

// ensureUsageTicker spawns the per-minute usage reporter the first time
// any tunnel sees activity. The goroutine exits on Shutdown.
func (p *Plain) ensureUsageTicker() {
	p.tickerOnce.Do(func() { go p.usageLoop() })
}

func (p *Plain) usageLoop() {
	t := time.NewTicker(usageReportInterval)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-t.C:
			p.emitUsage()
		}
	}
}

// emitUsage writes one line per tunnel that has either an active
// connection or new traffic since the last tick. Idle tunnels stay silent.
func (p *Plain) emitUsage() {
	type row struct {
		label string
		stats plainStats
	}
	var rows []row

	p.mu.Lock()
	for label, s := range p.stats {
		if s.active == 0 && !s.dirtySinceTick {
			continue
		}
		rows = append(rows, row{label: label, stats: *s})
		s.dirtySinceTick = false
	}
	p.mu.Unlock()

	for _, r := range rows {
		p.line("usage", r.label, fmt.Sprintf(
			"in=%s out=%s active=%d total-conns=%d",
			HumanBytes(r.stats.bytesIn),
			HumanBytes(r.stats.bytesOut),
			r.stats.active,
			r.stats.totalConns,
		))
	}
}

func (p *Plain) OnRedirect(label, from, to string) {
	p.line("redirect", label, from+" -> "+to)
}

func (p *Plain) OnShutdownPolicy(label string, code string, lt proto.LimitType, _ bool) {
	parts := []string{"limit-reached"}
	if code != "" {
		parts = append(parts, "code="+code)
	}
	if lt != "" {
		parts = append(parts, "type="+string(lt))
	}
	p.line("policy", label, strings.Join(parts, " "))
	if hint := PolicyHint(lt); hint != "" {
		p.line("policy", label, hint)
	}
}

func (p *Plain) line(event, label, msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ts := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	if label != "" {
		fmt.Fprintf(p.out, "%s %s [%s] %s\n", ts, event, label, msg)
		return
	}
	fmt.Fprintf(p.out, "%s %s %s\n", ts, event, msg)
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

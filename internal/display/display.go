package display

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/proto"
	"github.com/localport/agent/internal/tunnel"
)

// ANSI escape codes. Disable with NO_COLOR=1.
const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
	white   = "\033[37m"
)

// Display is the agent's line-oriented status output. It implements
// tunnel.EventHandler and writes timestamped lines to stderr.
type Display struct {
	out io.Writer

	mu         sync.Mutex
	noColor    bool
	protoOf    map[string]string
	labelWidth int
}

var _ tunnel.EventHandler = (*Display)(nil)

func New() *Display {
	_, nc := os.LookupEnv("NO_COLOR")
	return &Display{
		out:     os.Stderr,
		noColor: nc,
		protoOf: make(map[string]string),
	}
}

// Banner prints the once-per-process header that lists every configured
// endpoint along with its region and edge address.
func (d *Display) Banner(version string, cfg *config.Config) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.labelWidth = 7
	for _, s := range cfg.Specs {
		for _, ep := range s.Endpoints {
			d.protoOf[ep.Name] = ep.Protocol
			if len(ep.Name) > d.labelWidth {
				d.labelWidth = len(ep.Name)
			}
		}
	}

	fmt.Fprintln(d.out)
	fmt.Fprintf(d.out, "  %s %s\n", d.c(bold+cyan, "localport"), d.c(dim, version))
	fmt.Fprintf(d.out, "  %s\n", d.c(dim, strings.Repeat("─", 40)))

	if len(cfg.Specs) == 1 {
		s := cfg.Specs[0]
		d.specHeader(s, true)
		fmt.Fprintln(d.out)
		d.endpointTable(s.Endpoints)
	} else {
		for _, s := range cfg.Specs {
			d.specHeader(s, false)
			d.endpointTable(s.Endpoints)
		}
	}
	fmt.Fprintln(d.out)
}

func (d *Display) specHeader(s config.Spec, single bool) {
	region := s.Region
	if region == "" {
		region = "auto"
	}
	if single {
		fmt.Fprintf(d.out, "  %s %s %s\n",
			d.c(dim, pad("region", 8)),
			d.c(cyan+bold, region),
			d.c(dim, "· "+s.Edge))
		if !s.UseTLS {
			fmt.Fprintf(d.out, "  %s %s\n",
				d.c(dim, pad("tls", 8)),
				d.c(yellow, "off (development)"))
		}
		return
	}
	sep := max(2, 34-len(s.Edge)-len(region))
	fmt.Fprintln(d.out)
	fmt.Fprintf(d.out, "  %s %s %s %s\n",
		d.c(dim, "──"),
		d.c(cyan+bold, region),
		d.c(dim, "· "+s.Edge),
		d.c(dim, strings.Repeat("─", sep)))
	if !s.UseTLS {
		fmt.Fprintf(d.out, "  %s %s\n",
			d.c(dim, "   tls"),
			d.c(yellow, "off (development)"))
	}
}

func (d *Display) endpointTable(eps []config.Endpoint) {
	nameW, protoW := 4, 5
	for _, ep := range eps {
		nameW = max(nameW, len(ep.Name))
		protoW = max(protoW, len(ep.Protocol))
	}
	nameW += 2
	protoW += 2

	fmt.Fprintf(d.out, "  %s  %s  %s\n",
		d.c(dim, pad("NAME", nameW)),
		d.c(dim, pad("PROTO", protoW)),
		d.c(dim, "LOCAL"))
	for _, ep := range eps {
		fmt.Fprintf(d.out, "  %s  %s  %s\n",
			d.c(bold, pad(ep.Name, nameW)),
			d.c(protoColor(ep.Protocol), pad(ep.Protocol, protoW)),
			ep.Local)
	}
}

func (d *Display) Shutdown() {
	d.mu.Lock()
	defer d.mu.Unlock()
	fmt.Fprintf(d.out, "\n%s  %s\n", d.ts(), d.c(dim, "shutting down..."))
}

// EventHandler

func (d *Display) OnStateChange(label string, _, to tunnel.State) {
	switch to {
	case tunnel.StateConnecting:
		d.log(label, d.c(yellow, "◌ connecting..."))
	case tunnel.StateReconnecting:
		d.log(label, d.c(yellow, "◌ reconnecting..."))
	case tunnel.StateStopped:
		d.log(label, d.c(red, "✕ stopped"))
	}
}

func (d *Display) OnConnected(label string, info tunnel.Info) {
	d.mu.Lock()
	defer d.mu.Unlock()

	fmt.Fprintf(d.out, "%s  %s  %s\n", d.ts(), d.lbl(label), d.c(green+bold, "● online"))

	urls := info.URLs
	if len(urls) == 0 && info.PublicURL != "" {
		urls = []string{info.PublicURL}
	}
	for _, u := range urls {
		fmt.Fprintf(d.out, "%s  %s    %s\n", d.ts(), d.lbl(label), d.c(white+bold, u))
	}
	if info.Mode != "" {
		fmt.Fprintf(d.out, "%s  %s    %s %s  %s %s\n",
			d.ts(), d.lbl(label),
			d.c(dim, "mode:"), info.Mode,
			d.c(dim, "proto:"), info.Protocol)
	}
}

func (d *Display) OnDisconnected(label string, err error) {
	msg := "disconnected"
	if err != nil {
		msg = "disconnected: " + err.Error()
	}
	d.log(label, d.c(yellow, "◌ "+msg))
}

func (d *Display) OnError(label string, err error) {
	d.log(label, d.c(red, "✕ "+err.Error()))
}

func (d *Display) OnDataConn(label, connID, local string) {
	d.log(label, fmt.Sprintf("%s %s  %s",
		d.c(protoColor(d.protoOf[label]), "⇄"), local, d.c(dim, connID)))
}

func (d *Display) OnRedirect(label, from, to string) {
	d.log(label, fmt.Sprintf("%s %s %s %s",
		d.c(yellow, "→"),
		d.c(dim, "redirect"),
		d.c(dim, from+" →"),
		d.c(white+bold, to)))
}

func (d *Display) OnShutdownPolicy(label string, code string, lt proto.LimitType, _ bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	fmt.Fprintf(d.out, "%s  %s  %s\n", d.ts(), d.lbl(label), d.c(red+bold, "✕ limit reached"))

	var parts []string
	if code != "" {
		parts = append(parts, "code: "+code)
	}
	if lt != "" {
		parts = append(parts, "type: "+string(lt))
	}
	if len(parts) > 0 {
		fmt.Fprintf(d.out, "%s  %s    %s\n", d.ts(), d.lbl(label),
			d.c(dim, strings.Join(parts, "  ")))
	}
	if hint := policyHint(code, lt); hint != "" {
		fmt.Fprintf(d.out, "%s  %s    %s\n", d.ts(), d.lbl(label), d.c(dim, hint))
	}
}

func (d *Display) log(label, msg string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	fmt.Fprintf(d.out, "%s  %s  %s\n", d.ts(), d.lbl(label), msg)
}

func (d *Display) ts() string { return d.c(dim, time.Now().Format("15:04:05")) }

func (d *Display) lbl(name string) string {
	w := max(d.labelWidth, len(name))
	return d.c(cyan+bold, pad(name, w))
}

func (d *Display) c(code, text string) string {
	if d.noColor {
		return text
	}
	return code + text + reset
}

func protoColor(p string) string {
	switch p {
	case "http":
		return green
	case "tcp":
		return blue
	case "tls":
		return magenta
	}
	return white
}

func pad(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

func policyHint(code string, lt proto.LimitType) string {
	switch lt {
	case proto.LimitBandwidth:
		return "bandwidth limit reached — wait for the billing cycle to reset or upgrade your plan"
	case proto.LimitClientConnections:
		return "client connection limit reached — disconnect another client or upgrade"
	case proto.LimitTunnelCount:
		return "tunnel limit reached — remove a tunnel or upgrade your plan"
	}
	if strings.EqualFold(code, "TK003") {
		return "token is invalid or expired — rotate it from the dashboard"
	}
	return ""
}

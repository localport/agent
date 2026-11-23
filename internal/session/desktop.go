package session

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/launcher"
)

const (
	// desktopDialTimeout bounds the dial of a desktop target.
	desktopDialTimeout = 10 * time.Second
	// desktopClientWait bounds the handshake's wait for the client, from the
	// channel's accept to its last client read before the key question.
	desktopClientWait = 30 * time.Second
	// reqDesktopEnd is the channel request telling the client why the agent
	// ended a desktop channel; its payload is one string holding the reason.
	reqDesktopEnd = "end@localport.io"
	// The channel type of each desktop kind; the open carries no payload.
	chanVNC = "vnc@localport.io"
	chanRDP = "rdp@localport.io"
)

// desktopChannelType is the channel type a desktop kind's connection serves,
// or "" for a kind that is not a desktop kind.
func desktopChannelType(kind string) string {
	switch kind {
	case "vnc":
		return chanVNC
	case "rdp":
		return chanRDP
	}
	return ""
}

// isDesktopKind reports whether kind is a desktop kind: one channel to the
// configured target, dialed by the agent process.
func isDesktopKind(kind string) bool { return desktopChannelType(kind) != "" }

// desktopChannel is the one channel of a desktop connection, guarded by the
// connection's mu: the dial's cancel until the dial returns, then the
// accepted channel and the target connection until either ends.
type desktopChannel struct {
	cancel context.CancelFunc
	ch     ssh.Channel
	target net.Conn
	// stopped is set once the relay ended or the end was told; the end
	// request goes out at most once and never after the channel stopped.
	stopped bool
	// endReason is the connection's end reason when it ended before the
	// channel was accepted; the open goroutine tells it instead.
	endReason string
	// detail names what ended the open when it ended the connection with no
	// reason (endDetail, a dial's refusal code); the end line carries it.
	detail string
}

// Clipboard decision vocabulary: the direction text moves (copy from the
// device to the browser, paste the other way) and the filter's outcome.
const (
	clipboardCopy         = "copy"
	clipboardPaste        = "paste"
	clipboardAllowed      = "allowed"
	clipboardDeniedPolicy = "denied_policy"
	clipboardDeniedSize   = "denied_size"
	clipboardDeniedFormat = "denied_format"
)

// ClipboardDecision is one clipboard transfer decision of a desktop
// connection, never its content: SessionID is the canonical UUID of the
// stream the connection runs on now, Kind vnc or rdp, Bytes the text size
// the decision was about, At the decision time.
type ClipboardDecision struct {
	SessionID string
	Kind      string
	Direction string
	Outcome   string
	Bytes     int64
	At        time.Time
}

// noteClipboard reports one clipboard decision of c's desktop connection to
// ServerConfig.OnClipboard, which must not block.
func (c *conn) noteClipboard(kind, direction, outcome string, n int64) {
	if c.s.cfg.OnClipboard == nil {
		return
	}
	c.s.cfg.OnClipboard(ClipboardDecision{
		SessionID: c.adm.Load().sessionID, Kind: kind, Direction: direction, Outcome: outcome,
		Bytes: n, At: c.s.cfg.clock.Now(),
	})
}

// desktopTarget is the configured address of a desktop kind.
func (s *Server) desktopTarget(kind string) string {
	switch kind {
	case "vnc":
		return s.cfg.VNCTarget
	case "rdp":
		return s.cfg.RDPTarget
	}
	return ""
}

// openDesktop serves the channel open of a desktop connection: one channel
// of its kind's type with an empty payload, relayed to the configured
// target after the kind's handshake. Any other channel is refused. The
// connection ends with its one channel, when that channel is refused after
// the dial started, or when an open is refused before any channel
// registered, so a refused client does not hold a session slot. It never
// blocks the accept loop: the dial runs on its own goroutine, joined by wg.
func (c *conn) openDesktop(nc ssh.NewChannel, kind string, wg *sync.WaitGroup) {
	if want := desktopChannelType(kind); nc.ChannelType() != want || len(nc.ExtraData()) != 0 {
		_ = nc.Reject(ssh.Prohibited, "a "+kind+" connection serves only its "+want+" channel, with no payload")
		c.mu.Lock()
		var d *desktopChannel
		if !c.ended && c.desktop == nil {
			d = &desktopChannel{cancel: func() {}}
			c.desktop = d
		}
		c.mu.Unlock()
		if d != nil {
			c.desktopDone(d)
		}
		return
	}
	c.mu.Lock()
	if c.ended || c.desktop != nil {
		c.mu.Unlock()
		_ = nc.Reject(ssh.ResourceShortage, "channel limit reached")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), desktopDialTimeout)
	d := &desktopChannel{cancel: cancel}
	c.desktop = d
	c.mu.Unlock()
	wg.Go(func() {
		// A check that ends the connection leaves the end to run (c.fail),
		// which tells the client its reason; every other return ends it here.
		failed := false
		defer func() {
			if !failed {
				c.desktopDone(d)
			}
		}()
		dial := (&net.Dialer{}).DialContext
		if c.s.cfg.dialDesktop != nil {
			dial = c.s.cfg.dialDesktop
		}
		target, err := dial(ctx, "tcp", c.s.desktopTarget(kind))
		cancel()
		c.mu.Lock()
		ended, reason := c.ended, d.endReason
		if err == nil && !ended {
			d.target = target
		}
		c.mu.Unlock()
		switch {
		case ended:
			// The connection ended during the dial: its reason, not the
			// cancelled dial's, is why the channel is refused.
			if err == nil {
				_ = target.Close()
			}
			_ = nc.Reject(ssh.ConnectionFailed, endRefusal(reason))
			return
		case err != nil:
			code := desktopDialCode(err)
			c.noteDesktopEnd(d, code)
			_ = nc.Reject(ssh.ConnectionFailed, code)
			return
		}
		ch, reqs, err := nc.Accept()
		if err != nil {
			_ = target.Close()
			return
		}
		wg.Go(func() { discardChannelRequests(reqs) })
		checkCtx, checkCancel := context.WithCancel(context.Background())
		defer checkCancel()
		c.mu.Lock()
		ended, reason = c.ended, d.endReason
		if !ended {
			// The end cancels the handshake check's pin wait from now on.
			d.ch, d.cancel = ch, checkCancel
		}
		c.mu.Unlock()
		if ended {
			// The end closed only the target; the client still learns why.
			_ = target.Close()
			if reason != "" {
				_, _ = ch.SendRequest(reqDesktopEnd, false, ssh.Marshal(struct{ Reason string }{reason}))
			}
			_ = ch.Close()
			return
		}
		h := &desktopHandshake{c: c, ch: ch, target: target, fromClient: bufio.NewReader(ch),
			keys: c.s.cfg.DesktopKeys, kind: kind, addr: c.s.desktopTarget(kind), timeout: c.s.cfg.desktopCheckTimeout,
			wait: c.startClientWait(wg)}
		defer h.wait.end()
		if h.keys == nil {
			h.keys = noDesktopKeys{}
		}
		if h.timeout == 0 {
			h.timeout = desktopTargetTimeout
		}
		var toTarget, toClient func() string
		if kind == "rdp" {
			g := &rdpGateway{desktopHandshake: h}
			if reason, err = g.run(checkCtx); reason == "" && err == nil {
				filter := newRDPFilter(g)
				toTarget, toClient = filter.pumpToTarget, filter.pumpToClient
			}
		} else {
			h.fromTarget = bufio.NewReaderSize(target, rfbServerBuffer)
			check := &rfbCheck{desktopHandshake: h}
			if reason, err = check.run(checkCtx); reason == "" && err == nil {
				filter := newRFBFilter(check, target)
				if err = filter.handshake(); errors.Is(err, errRFBViolation) {
					reason, err = filter.end(err), nil
				}
				toTarget, toClient = filter.pumpToTarget, filter.pumpToClient
			}
		}
		reason, err = handshakeOutcome(reason, err)
		switch {
		case errors.Is(err, errDesktopEnded):
			// The client wait expired: its end tells the client.
			failed = true
			return
		case err != nil:
			c.noteDesktopEnd(d, endDetail(err))
			return
		case reason != "":
			failed = true
			c.fail(reason)
			return
		}
		if reason = c.relayDesktop(ch, target, toTarget, toClient); reason != "" {
			failed = true
			c.fail(reason)
		}
	})
}

// desktopHandshake is what both desktop handshakes share: the accepted
// channel, the target connection, the buffered client reader the relay
// continues from, the pin store and the client wait. Only the open
// goroutine uses it.
type desktopHandshake struct {
	c          *conn
	ch         ssh.Channel
	target     net.Conn
	fromClient *bufio.Reader
	// fromTarget is the vnc check's buffered target reader; the rdp gateway
	// reads the target unbuffered, since TLS runs on the same connection.
	fromTarget *bufio.Reader
	keys       DesktopKeys
	kind, addr string
	// timeout is the deadline of each target read and write.
	timeout time.Duration
	wait    *clientWait
}

// handshakeSide is the side of a desktop handshake an I/O error came from.
type handshakeSide uint8

const (
	sideClient handshakeSide = iota + 1
	sideTarget
)

func (s handshakeSide) String() string {
	if s == sideTarget {
		return "target"
	}
	return "client"
}

// handshakeFault is what went wrong in a desktop handshake.
type handshakeFault uint8

const (
	// faultDeadline: a target read or write passed its deadline.
	faultDeadline handshakeFault = iota + 1
	// faultClosed: an EOF or I/O error, a short read included.
	faultClosed
	// faultMalformed: bytes that do not parse, or a refused form.
	faultMalformed
)

func (f handshakeFault) String() string {
	switch f {
	case faultDeadline:
		return "deadline"
	case faultClosed:
		return "closed"
	}
	return "malformed"
}

// handshakeError is a failure of a desktop handshake, typed by side and
// fault so the end code never depends on error text.
type handshakeError struct {
	side  handshakeSide
	fault handshakeFault
	err   error
}

func (e *handshakeError) Error() string {
	return fmt.Sprintf("desktop handshake (%s): %v", e.side, e.err)
}

func (e *handshakeError) Unwrap() error { return e.err }

// clientIOError types an error reading or writing the channel.
func clientIOError(err error) error {
	return &handshakeError{side: sideClient, fault: faultClosed, err: err}
}

// targetIOError types an error reading or writing the target.
func targetIOError(err error) error {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return &handshakeError{side: sideTarget, fault: faultDeadline, err: err}
	}
	return &handshakeError{side: sideTarget, fault: faultClosed, err: err}
}

// malformed types bytes from side that do not parse or take a refused form.
func malformed(side handshakeSide, format string, args ...any) error {
	return &handshakeError{side: side, fault: faultMalformed, err: fmt.Errorf(format, args...)}
}

// targetEnded reports whether err is the target's EOF, I/O error or deadline.
func targetEnded(err error) bool {
	var he *handshakeError
	return errors.As(err, &he) && he.side == sideTarget && he.fault != faultMalformed
}

// endDetail names what ended a desktop open for its end line, by type
// only, never by error text: the server's refusal of the VNC handshake,
// the side and fault of a handshake error, or "internal".
func endDetail(err error) string {
	var he *handshakeError
	switch {
	case errors.Is(err, errRFBClosed):
		return "target_refused"
	case errors.As(err, &he):
		return he.side.String() + "_" + he.fault.String()
	}
	return "internal"
}

// errDesktopEnded marks a handshake interrupted by the connection's end,
// which reports its own reason.
var errDesktopEnded = errors.New("desktop connection ended")

// handshakeOutcome maps a handshake's result to the end of the connection,
// first match wins: a target deadline ends desktop_handshake_timeout, a
// target EOF or I/O error desktop_target_closed, a client error ends it
// "exited" with no reason told (err is kept), and malformed bytes end
// desktop_handshake_invalid. Any other error is the connection's own end.
func handshakeOutcome(reason string, err error) (string, error) {
	var he *handshakeError
	switch {
	case err == nil:
		return reason, nil
	case !errors.As(err, &he):
		return "", err
	case he.fault == faultDeadline:
		return CloseDesktopHandshakeTimeout, nil
	case he.fault == faultClosed && he.side == sideTarget:
		return CloseDesktopTargetClosed, nil
	case he.fault == faultClosed:
		return "", err
	}
	return CloseDesktopHandshake, nil
}

// readClient reads n client bytes; they count as activity.
func (h *desktopHandshake) readClient(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(h.fromClient, b); err != nil {
		return nil, clientIOError(err)
	}
	h.c.active()
	return b, nil
}

func (h *desktopHandshake) writeClient(b []byte) error {
	if _, err := h.ch.Write(b); err != nil {
		return clientIOError(err)
	}
	return nil
}

// readTarget reads n target bytes from r within the target deadline.
func (h *desktopHandshake) readTarget(r io.Reader, n int) ([]byte, error) {
	_ = h.target.SetReadDeadline(time.Now().Add(h.timeout))
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, targetIOError(err)
	}
	return b, nil
}

// writeTarget writes b to the target within the target deadline.
func (h *desktopHandshake) writeTarget(b []byte) error {
	_ = h.target.SetWriteDeadline(time.Now().Add(h.timeout))
	if _, err := h.target.Write(b); err != nil {
		return targetIOError(err)
	}
	return nil
}

// clientWaitDone stops the client wait after the handshake's last client
// read before the key question; errDesktopEnded when the wait had expired.
func (h *desktopHandshake) clientWaitDone() error {
	if !h.wait.end() {
		return errDesktopEnded
	}
	return nil
}

// trust runs the key step both kinds share for the target key sum: a
// pinned, different key ends desktop_key_changed; otherwise the client is
// asked (payload built with whether the key is pinned), a refusal ends
// desktop_key_rejected, and a key not pinned is pinned on first use. A
// store failure ends desktop_key_unavailable. "" lets the handshake go on.
func (h *desktopHandshake) trust(ctx context.Context, sum [32]byte, payload func(pinned bool) []byte) (string, error) {
	pinned, held, err := h.keys.Lookup(h.kind, h.addr)
	if err != nil {
		h.c.s.log("session: desktop key of %s: %v", h.addr, err)
		return CloseDesktopKeyUnavailable, nil
	}
	if held && pinned != sum {
		h.c.s.log("session: desktop target %s presented key %x, pinned %x", h.addr, sum, pinned)
		return CloseDesktopKeyChanged, nil
	}
	ok, err := h.ch.SendRequest(reqDesktopKey, true, payload(held))
	if err != nil {
		return "", clientIOError(err)
	}
	if !ok {
		return CloseDesktopKeyRejected, nil
	}
	if held {
		return "", nil
	}
	switch r, err := h.keys.Pin(ctx, h.kind, h.addr, sum); {
	case err != nil:
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		h.c.s.log("session: pin desktop key of %s: %v", h.addr, err)
		return CloseDesktopKeyUnavailable, nil
	case r == identity.PinChanged:
		h.c.s.log("session: desktop target %s presented key %x, another was pinned first", h.addr, sum)
		return CloseDesktopKeyChanged, nil
	}
	return "", nil
}

// clientWait is the handshake's bound on the client: unless end runs
// first, it ends the connection desktop_handshake_timeout.
type clientWait struct {
	c       *conn
	stop    func() bool
	done    chan struct{}
	over    bool
	expired bool
}

// startClientWait arms the client wait on the server clock; its watcher
// goroutine is joined by wg and leaves at end.
func (c *conn) startClientWait(wg *sync.WaitGroup) *clientWait {
	fire, stop := c.s.cfg.clock.NewTimer(desktopClientWait)
	w := &clientWait{c: c, stop: stop, done: make(chan struct{})}
	wg.Go(func() {
		select {
		case <-fire:
			c.fail(CloseDesktopHandshakeTimeout)
		case <-w.done:
		}
	})
	return w
}

// end stops the wait and reports whether it stopped in time. When the timer
// had fired, the end of the connection runs (end records it itself, since
// the watcher may see done first). Called by the open goroutine only;
// repeat calls return the first answer.
func (w *clientWait) end() bool {
	if !w.over {
		w.over = true
		if w.expired = !w.stop(); w.expired {
			w.c.fail(CloseDesktopHandshakeTimeout)
		}
		close(w.done)
	}
	return !w.expired
}

// noDesktopKeys is the pin store of a server configured without one: every
// lookup fails, so a server key or a pinned-target rule ends the connection.
type noDesktopKeys struct{}

var errNoDesktopKeys = errors.New("no desktop key store")

func (noDesktopKeys) Lookup(string, string) ([32]byte, bool, error) {
	return [32]byte{}, false, errNoDesktopKeys
}

func (noDesktopKeys) Pin(context.Context, string, string, [32]byte) (identity.PinResult, error) {
	return 0, errNoDesktopKeys
}

// relayDesktop runs both directions of a desktop connection until either
// ends: neither desktop protocol has a half-close, so one side's end is the
// session's. A pump returns "" for the client's close, and the relay then
// closes the channel and the target and waits for the other pump. A pump's
// reason (a violation, a refusal, the target's end) closes
// the target only and is returned at once: the channel stays open so the
// connection's end can tell the client why, and that end's close of the
// channel stops the other pump.
func (c *conn) relayDesktop(ch ssh.Channel, target net.Conn, toTarget, toClient func() string) string {
	done := make(chan string, 2)
	go func() { done <- toTarget() }()
	go func() { done <- toClient() }()
	if reason := <-done; reason != "" {
		_ = target.Close()
		return reason
	}
	_ = ch.Close()
	_ = target.Close()
	<-done
	return ""
}

// endRefusal is the refusal message of a channel whose connection ended
// before it opened: the end reason, or "exited" when the end had none.
func endRefusal(reason string) string {
	if reason == "" {
		return CloseExited
	}
	return reason
}

// discardChannelRequests refuses every request of a desktop channel; none is
// served and none counts as activity.
func discardChannelRequests(reqs <-chan *ssh.Request) {
	for r := range reqs {
		if r.WantReply {
			_ = r.Reply(false, nil)
		}
	}
}

// desktopDialCode is the refusal code of a failed target dial.
func desktopDialCode(err error) string {
	if errConnRefused(err) {
		return launcher.FwdCodeName(launcher.FwdCodeConnectionRefused)
	}
	return launcher.FwdCodeName(launcher.FwdCodeUnreachable)
}

// noteDesktopEnd records detail for the connection's end line.
func (c *conn) noteDesktopEnd(d *desktopChannel, detail string) {
	c.mu.Lock()
	d.detail = detail
	c.mu.Unlock()
}

// logDesktopEnd logs a desktop connection's end once, from run, which
// decides it: the kind, the target, the reason ("exited" when it has none)
// and the open's detail when one was recorded. The detail explains only an
// end the open path caused, which is "exited"; an end decided otherwise
// (idle, shutdown, a kick) that raced the open's failure is logged without
// it. The line holds no error text and no bytes from either side.
func (c *conn) logDesktopEnd(reason string) {
	kind := c.adm.Load().Kind
	c.mu.Lock()
	var detail string
	if c.desktop != nil {
		detail = c.desktop.detail
	}
	c.mu.Unlock()
	if reason == "" {
		reason = CloseExited
	}
	if detail != "" && reason == CloseExited {
		reason += " (" + detail + ")"
	}
	c.s.log("session: %s desktop connection to %s ended: %s", kind, c.s.desktopTarget(kind), reason)
}

// desktopDone marks the desktop channel stopped and ends the connection,
// whose one channel it was.
func (c *conn) desktopDone(d *desktopChannel) {
	c.mu.Lock()
	d.stopped = true
	c.mu.Unlock()
	select {
	case c.allClosed <- struct{}{}:
	default:
	}
}

// endDesktop ends the desktop channel, if any, for the connection's end:
// it cancels a running dial, tells the client the reason when there is one
// and the channel has not stopped, and closes the channel and the target. A
// channel not accepted yet keeps the reason for its open goroutine, which
// refuses or tells with it while the connection still carries messages.
// Called by end with ended already set, so nothing registers after it.
func (c *conn) endDesktop(reason string) {
	c.mu.Lock()
	d := c.desktop
	if d == nil {
		c.mu.Unlock()
		return
	}
	cancel, ch, target, tell := d.cancel, d.ch, d.target, !d.stopped && reason != ""
	d.stopped = true
	if ch == nil {
		d.endReason = reason
	}
	c.mu.Unlock()
	cancel()
	// The end request goes out before the channel closes; closing the
	// target afterwards ends the relay's pumps.
	if ch != nil {
		if tell {
			_, _ = ch.SendRequest(reqDesktopEnd, false, ssh.Marshal(struct{ Reason string }{reason}))
		}
		_ = ch.Close()
	}
	if target != nil {
		_ = target.Close()
	}
}

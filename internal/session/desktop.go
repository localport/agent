package session

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/launcher"
)

const (
	// desktopDialTimeout bounds the dial of a desktop target.
	desktopDialTimeout = 10 * time.Second
	// reqDesktopEnd is the channel request telling the client why the agent
	// ended a desktop channel; its payload is one string holding the reason.
	reqDesktopEnd = "end@localport.io"
)

// isDesktopKind reports whether kind is a desktop kind the agent serves: its
// connection carries one channel to the configured target, dialed by the
// agent process.
func isDesktopKind(kind string) bool { return kind == "vnc" }

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
}

// desktopTarget is the configured address of a desktop kind.
func (s *Server) desktopTarget(kind string) string {
	if kind == "vnc" {
		return s.cfg.VNCTarget
	}
	return ""
}

// openDesktop serves the channel open of a desktop connection: one
// direct-tcpip channel, whatever address it names, relayed to the
// configured target. Any other channel is refused. The connection ends with
// its one channel, or when that channel is refused. It never blocks the
// accept loop: the dial runs on its own goroutine, joined by wg.
func (c *conn) openDesktop(nc ssh.NewChannel, kind string, wg *sync.WaitGroup) {
	if nc.ChannelType() != chanDirectTCPIP {
		_ = nc.Reject(ssh.Prohibited, "a desktop connection serves only its direct-tcpip channel")
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
	if !validDirectTCPIP(nc.ExtraData()) {
		cancel()
		_ = nc.Reject(ssh.ConnectionFailed, launcher.FwdCodeName(launcher.FwdCodeInvalid))
		c.desktopDone(d)
		return
	}
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
			_ = nc.Reject(ssh.ConnectionFailed, desktopDialCode(err))
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
		check := &rfbCheck{c: c, ch: ch, target: target, fromClient: bufio.NewReader(ch), fromTarget: bufio.NewReader(target),
			keys: c.s.cfg.DesktopKeys, kind: kind, addr: c.s.desktopTarget(kind), timeout: c.s.cfg.desktopCheckTimeout}
		if check.keys == nil {
			check.keys = noDesktopKeys{}
		}
		if check.timeout == 0 {
			check.timeout = desktopCheckTimeout
		}
		reason, err = check.run(checkCtx)
		switch {
		case err != nil:
			return
		case reason != "":
			failed = true
			c.fail(reason)
			return
		}
		c.relayDesktop(ch, target, check.fromClient, check.fromTarget)
	})
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

// relayDesktop copies between the desktop channel and the target until
// either direction ends, then closes both: a remote framebuffer protocol has
// no half-close, so one side's end is the session's. It reads from the
// handshake check's buffered readers, so bytes they read ahead come first.
// Only client bytes are activity for the idle timer.
func (c *conn) relayDesktop(ch ssh.Channel, target net.Conn, fromClient, fromTarget io.Reader) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(activityWriter{target, c}, fromClient)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(ch, fromTarget)
		done <- struct{}{}
	}()
	<-done
	_ = ch.Close()
	_ = target.Close()
	<-done
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

// validDirectTCPIP reports whether payload is a well-formed direct-tcpip open
// (RFC 4254 7.2), with the bounds forwarder.local applies.
func validDirectTCPIP(payload []byte) bool {
	var p struct {
		Host     string
		Port     uint32
		OrigHost string
		OrigPort uint32
	}
	return ssh.Unmarshal(payload, &p) == nil && p.Host != "" && len(p.Host) <= launcher.MaxForwardHost &&
		bytes.IndexByte([]byte(p.Host), 0) < 0 && p.Port >= 1 && p.Port <= 65535
}

// desktopDialCode is the refusal code of a failed target dial.
func desktopDialCode(err error) string {
	if errConnRefused(err) {
		return launcher.FwdCodeName(launcher.FwdCodeConnectionRefused)
	}
	return launcher.FwdCodeName(launcher.FwdCodeUnreachable)
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
	// The client is told before the target closes: the target's close ends
	// the relay, which closes the channel.
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

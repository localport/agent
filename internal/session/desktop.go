package session

import (
	"bytes"
	"context"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

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
		defer c.desktopDone(d)
		dial := (&net.Dialer{}).DialContext
		if c.s.cfg.dialDesktop != nil {
			dial = c.s.cfg.dialDesktop
		}
		target, err := dial(ctx, "tcp", c.s.desktopTarget(kind))
		cancel()
		if err != nil {
			_ = nc.Reject(ssh.ConnectionFailed, desktopDialCode(err))
			return
		}
		c.mu.Lock()
		ended := c.ended
		if !ended {
			d.target = target
		}
		c.mu.Unlock()
		if ended {
			_ = target.Close()
			_ = nc.Reject(ssh.ConnectionFailed, "the connection ended")
			return
		}
		ch, reqs, err := nc.Accept()
		if err != nil {
			_ = target.Close()
			return
		}
		wg.Go(func() { discardChannelRequests(reqs) })
		c.mu.Lock()
		ended = c.ended
		if !ended {
			d.ch = ch
		}
		c.mu.Unlock()
		if ended {
			_ = ch.Close()
			_ = target.Close()
			return
		}
		c.relay(ch, target.(launcher.ForwardConn), false)
	})
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
// and the channel has not stopped, and closes the channel and the target.
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
	c.mu.Unlock()
	cancel()
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

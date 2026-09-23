package proto

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

// deadlineConn records write-deadline calls and discards writes, so a test can
// assert Send bounds its write and then clears the deadline.
type deadlineConn struct {
	net.Conn
	setCalls []time.Time
}

func (c *deadlineConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *deadlineConn) SetWriteDeadline(t time.Time) error {
	c.setCalls = append(c.setCalls, t)
	return nil
}

// Send must arm a write deadline before writing and clear it (zero time) after,
// so a stuck socket can't wedge the write, and the data path can reuse the raw
// conn for io.Copy with no lingering deadline.
func TestSendBoundsAndClearsWriteDeadline(t *testing.T) {
	dc := &deadlineConn{}
	c := NewConn(dc)

	before := time.Now()
	if err := c.SendHeartbeat(); err != nil {
		t.Fatalf("SendHeartbeat: %v", err)
	}

	if len(dc.setCalls) != 2 {
		t.Fatalf("SetWriteDeadline called %d times, want 2 (arm + clear)", len(dc.setCalls))
	}
	// First call arms a future deadline within the configured window.
	armed := dc.setCalls[0]
	if !armed.After(before) || armed.After(before.Add(defaultWriteTimeout+time.Second)) {
		t.Fatalf("armed deadline %v not within (now, now+%v]", armed, defaultWriteTimeout)
	}
	// Second call clears it (zero time).
	if !dc.setCalls[1].IsZero() {
		t.Fatalf("deadline not cleared: %v", dc.setCalls[1])
	}
}

// A zero writeTimeout disables the deadline entirely (no SetWriteDeadline
// calls), the escape hatch for callers that opt out.
func TestSendNoDeadlineWhenDisabled(t *testing.T) {
	dc := &deadlineConn{}
	c := NewConn(dc)
	c.writeTimeout = 0

	if err := c.SendHeartbeat(); err != nil {
		t.Fatalf("SendHeartbeat: %v", err)
	}
	if len(dc.setCalls) != 0 {
		t.Fatalf("SetWriteDeadline called %d times with timeout disabled, want 0", len(dc.setCalls))
	}
}

// countingConn counts Write calls.
type countingConn struct {
	net.Conn
	buf    bytes.Buffer
	writes int
}

func (c *countingConn) Write(p []byte) (int, error) {
	c.writes++
	return c.buf.Write(p)
}
func (c *countingConn) SetWriteDeadline(time.Time) error { return nil }

// Each frame is sent in one Write.
func TestSendEmitsOneWritePerFrame(t *testing.T) {
	cc := &countingConn{}
	c := NewConn(cc)

	if err := c.Send(MsgRegister, &RegisterPayload{Token: "tok", ClientName: "agent-1"}); err != nil {
		t.Fatal(err)
	}
	if cc.writes != 1 {
		t.Fatalf("payload frame took %d writes, want 1", cc.writes)
	}

	cc.writes = 0
	if err := c.Send(MsgHeartbeat, nil); err != nil {
		t.Fatal(err)
	}
	if cc.writes != 1 {
		t.Fatalf("bodyless frame took %d writes, want 1", cc.writes)
	}

	// The written bytes parse as two frames.
	rc := NewConn(&readOnlyConn{r: bytes.NewReader(cc.buf.Bytes())})
	if mt, body, err := rc.Recv(); err != nil || mt != MsgRegister || len(body) == 0 {
		t.Fatalf("first frame: type=%v bodyLen=%d err=%v", mt, len(body), err)
	}
	if mt, body, err := rc.Recv(); err != nil || mt != MsgHeartbeat || body != nil {
		t.Fatalf("second frame: type=%v body=%v err=%v", mt, body, err)
	}
}

type readOnlyConn struct {
	net.Conn
	r *bytes.Reader
}

func (c *readOnlyConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// Parsers sanitize displayed fields and keep matched or dialed fields byte for
// byte.
func TestParsersStripDisplayFieldsAndPreserveIdentifiers(t *testing.T) {
	// JSON strings carry control bytes only as escapes. escJSON is the wire
	// form and esc the decoded value.
	const escJSON = `\u001b[2J\u0007`
	const esc = "\x1b[2J\x07"

	ack, err := ParseRegisterAck([]byte(`{
		"tunnel_name":"a` + escJSON + `","region":"eu` + escJSON + `","region_name":"E` + escJSON + `",
		"public_url":"https://x` + escJSON + `","urls":["https://a` + escJSON + `","https://b` + escJSON + `"],
		"subdomain":"s` + escJSON + `","mode":"m` + escJSON + `","protocol":"p` + escJSON + `",
		"error":"e` + escJSON + `","error_code":"C` + escJSON + `","limit_type":"bandwidth` + escJSON + `",
		"ports":[{"port":80,"protocol":"http` + escJSON + `"}],
		"tunnel_id":"tun_` + escJSON + `","session_id":"sess` + escJSON + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]string{
		"tunnel_name": ack.TunnelName, "region": ack.Region, "region_name": ack.RegionName,
		"public_url": ack.PublicURL, "urls[0]": ack.URLs[0], "urls[1]": ack.URLs[1],
		"subdomain": ack.Subdomain, "mode": ack.Mode, "protocol": ack.Protocol,
		"error": ack.Error, "error_code": ack.ErrorCode,
		"limit_type": string(ack.LimitType), "ports[0].protocol": ack.Ports[0].Protocol,
	} {
		if strings.ContainsAny(got, "\x1b\x07") {
			t.Errorf("RegisterAck.%s kept a control character: %q", name, got)
		}
	}
	// Matched and dialed fields stay verbatim.
	if ack.SessionID != "sess"+esc {
		t.Errorf("session_id was altered: %q", ack.SessionID)
	}
	if ack.TunnelID != "tun_"+esc {
		t.Errorf("tunnel_id was altered: %q", ack.TunnelID)
	}

	nc, err := ParseNewConnection([]byte(`{"connection_id":"conn` + escJSON + `","remote_addr":"1.2.3.4:1` + escJSON + `","target_protocol":"tcp` + escJSON + `","consumer":"user:x` + escJSON + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]string{
		"remote_addr": nc.RemoteAddr, "target_protocol": nc.TargetProtocol, "consumer": nc.Consumer,
	} {
		if strings.ContainsAny(got, "\x1b\x07") {
			t.Errorf("NewConnection.%s kept a control character: %q", name, got)
		}
	}
	if nc.ConnectionID != "conn"+esc {
		t.Errorf("connection_id was altered: %q", nc.ConnectionID)
	}

	sd, err := ParseShutdown([]byte(`{"reason":"r` + escJSON + `","code":"X` + escJSON + `","limit_type":"blocked` + escJSON + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(sd.Reason+sd.Code+string(sd.LimitType), "\x1b\x07") {
		t.Errorf("Shutdown kept a control character: %+v", sd)
	}
	// An empty body parses.
	if got, err := ParseShutdown(nil); err != nil || got.Reason != "" {
		t.Errorf("ParseShutdown(nil) = %+v, %v", got, err)
	}

	ep, err := ParseError([]byte(`{"code":"C` + escJSON + `","message":"m` + escJSON + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(ep.Code+ep.Message, "\x1b\x07") {
		t.Errorf("Error kept a control character: %+v", ep)
	}

	rd, err := ParseRedirect([]byte(`{"edge_addr":"e1.eu.localport.dev` + escJSON + `","edge_id":"edge-1` + escJSON + `","reason":"rebalance` + escJSON + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(rd.Reason, "\x1b\x07") {
		t.Errorf("Redirect.reason kept a control character: %q", rd.Reason)
	}
	// edge_addr is dialed and checked by allowedRedirectHost.
	if rd.EdgeAddr != "e1.eu.localport.dev"+esc {
		t.Errorf("edge_addr was altered: %q", rd.EdgeAddr)
	}

	mb, err := ParseMuxBindAck([]byte(`{"success":false,"error":"no` + escJSON + `","code":"C` + escJSON + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(mb.Error+mb.Code, "\x1b\x07") {
		t.Errorf("MuxBindAck kept a control character: %+v", mb)
	}

	pu, err := ParsePortsUpdate([]byte(`{"version":7,"ports":[{"port":502,"protocol":"tcp` + escJSON + `"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(pu.Ports[0].Protocol, "\x1b\x07") {
		t.Errorf("PortsUpdate port protocol kept a control character: %q", pu.Ports[0].Protocol)
	}
}

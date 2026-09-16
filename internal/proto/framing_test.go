package proto

import (
	"bytes"
	"net"
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

	if err := c.Send(MsgRegister, &RegisterPayload{Token: "tok", ClientID: "agent-1"}); err != nil {
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

package proto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// pipeConns returns a connected pair with write deadlines disabled.
func pipeConns(t *testing.T) (*Conn, *Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	ca, cb := NewConn(a), NewConn(b)
	ca.writeTimeout, cb.writeTimeout = 0, 0
	return ca, cb
}

// sendAsync writes on a pipe, which blocks until the peer reads.
func sendAsync(t *testing.T, c *Conn, mt MessageType, payload any) <-chan error {
	t.Helper()
	errc := make(chan error, 1)
	go func() { errc <- c.Send(mt, payload) }()
	return errc
}

// Every frame the agent sends round-trips with its type and payload.
func TestFrameRoundTripPreservesTypeAndPayload(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mt      MessageType
		payload any
		check   func(*testing.T, []byte)
	}{
		{
			name: "register",
			mt:   MsgRegister,
			payload: &RegisterPayload{
				Token: "tok", Protocol: "tcp", ClientName: "laptop",
				Timestamp: 1700000000, Nonce: "n", AgentVersion: "v1", AgentOS: "linux/amd64",
			},
			check: func(t *testing.T, b []byte) {
				var p RegisterPayload
				mustJSON(t, b, &p)
				if p.Token != "tok" || p.Protocol != "tcp" || p.ClientName != "laptop" {
					t.Fatalf("register payload = %+v", p)
				}
				if strings.Contains(string(b), `"client_id"`) {
					t.Fatalf("register carries client_id: %s", b)
				}
				if p.AgentOS != "linux/amd64" || p.Nonce != "n" {
					t.Fatalf("register metadata lost: %+v", p)
				}
			},
		},
		{
			name:    "connection ready",
			mt:      MsgConnectionReady,
			payload: &ConnectionReadyPayload{ConnectionID: "conn-1", Status: 502},
			check: func(t *testing.T, b []byte) {
				var p ConnectionReadyPayload
				mustJSON(t, b, &p)
				if p.ConnectionID != "conn-1" || p.Status != 502 {
					t.Fatalf("connection ready payload = %+v", p)
				}
			},
		},
		{
			name:    "mux bind",
			mt:      MsgMuxBind,
			payload: &MuxBindPayload{Token: "tok", SessionID: "s1", Timestamp: 7, Nonce: "n"},
			check: func(t *testing.T, b []byte) {
				var p MuxBindPayload
				mustJSON(t, b, &p)
				if p.SessionID != "s1" || p.Timestamp != 7 {
					t.Fatalf("mux bind payload = %+v", p)
				}
				if strings.Contains(string(b), `"client_id"`) {
					t.Fatalf("mux bind carries client_id: %s", b)
				}
			},
		},
		{
			name:    "ports ack",
			mt:      MsgPortsAck,
			payload: &PortsAckPayload{Version: 42},
			check: func(t *testing.T, b []byte) {
				var p PortsAckPayload
				mustJSON(t, b, &p)
				if p.Version != 42 {
					t.Fatalf("ports ack version = %d, want 42", p.Version)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, r := pipeConns(t)
			errc := sendAsync(t, w, tc.mt, tc.payload)

			gotType, body, err := r.Recv()
			if err != nil {
				t.Fatalf("recv: %v", err)
			}
			if err := <-errc; err != nil {
				t.Fatalf("send: %v", err)
			}
			if gotType != tc.mt {
				t.Fatalf("type = %v, want %v", gotType, tc.mt)
			}
			tc.check(t, body)
		})
	}
}

// A heartbeat ack echoes the heartbeat timestamp.
func TestHeartbeatAckEchoesTheSenderTimestamp(t *testing.T) {
	w, r := pipeConns(t)

	errc := sendAsync(t, w, MsgHeartbeat, &HeartbeatPayload{Timestamp: 1234})
	mt, body, err := r.Recv()
	if err != nil {
		t.Fatalf("recv heartbeat: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}
	if mt != MsgHeartbeat {
		t.Fatalf("type = %v, want MsgHeartbeat", mt)
	}
	hb, err := ParseHeartbeat(body)
	if err != nil {
		t.Fatalf("parse heartbeat: %v", err)
	}

	ackErr := make(chan error, 1)
	go func() { ackErr <- r.SendHeartbeatAck(hb.Timestamp) }()
	mt, body, err = w.Recv()
	if err != nil {
		t.Fatalf("recv ack: %v", err)
	}
	if err := <-ackErr; err != nil {
		t.Fatalf("send ack: %v", err)
	}
	if mt != MsgHeartbeatAck {
		t.Fatalf("type = %v, want MsgHeartbeatAck", mt)
	}
	var ack HeartbeatAckPayload
	mustJSON(t, body, &ack)
	if ack.Timestamp != 1234 {
		t.Fatalf("ack timestamp = %d, want the 1234 that was sent", ack.Timestamp)
	}
}

// A nil payload sends a type with no body, and Recv returns a nil body.
func TestFrameWithNoPayload(t *testing.T) {
	w, r := pipeConns(t)
	errc := sendAsync(t, w, MsgHeartbeatAck, nil)

	mt, body, err := r.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("send: %v", err)
	}
	if mt != MsgHeartbeatAck {
		t.Fatalf("type = %v, want MsgHeartbeatAck", mt)
	}
	if body != nil {
		t.Fatalf("body = %q, want nil", body)
	}
}

// Shutdown with an empty body parses to an empty payload.
func TestParseShutdownAcceptsAnEmptyBody(t *testing.T) {
	p, err := ParseShutdown(nil)
	if err != nil {
		t.Fatalf("empty shutdown body: %v", err)
	}
	if p.Reason != "" || p.Code != "" {
		t.Fatalf("payload = %+v, want zero", p)
	}
}

// Send and Recv both refuse frames over MaxMessageSize.
func TestOversizeFrameRefusedOnSendAndOnRecv(t *testing.T) {
	w, r := pipeConns(t)

	big := &ErrorPayload{Message: strings.Repeat("x", MaxMessageSize)}
	if err := w.Send(MsgError, big); err == nil {
		t.Fatal("Send accepted a frame larger than MaxMessageSize")
	}

	// An oversized length from the peer is refused before allocation.
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[:4], MaxMessageSize+1)
	hdr[4] = byte(MsgError)
	go func() { _, _ = w.raw.Write(hdr[:]) }()

	// Without the check, Recv would block waiting for the body.
	if err := r.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("read deadline: %v", err)
	}
	if _, _, err := r.Recv(); err == nil {
		t.Fatal("Recv accepted a length over MaxMessageSize")
	}
}

// A zero length is invalid because the length includes the type byte.
func TestZeroLengthFrameRefused(t *testing.T) {
	w, r := pipeConns(t)

	go func() { _, _ = w.raw.Write([]byte{0, 0, 0, 0, byte(MsgHeartbeat)}) }()

	_, _, err := r.Recv()
	if err == nil {
		t.Fatal("Recv accepted a zero-length frame")
	}
	if !strings.Contains(err.Error(), "zero-length") {
		t.Fatalf("error = %v, want it to name the zero-length frame", err)
	}
}

// A body shorter than its header length is an error.
func TestTruncatedBodyIsAnError(t *testing.T) {
	w, r := pipeConns(t)

	go func() {
		var hdr [5]byte
		binary.BigEndian.PutUint32(hdr[:4], 1+64)
		hdr[4] = byte(MsgError)
		_, _ = w.raw.Write(hdr[:])
		_, _ = w.raw.Write([]byte(`{"code":"X"}`))
		w.raw.Close()
	}()

	if _, _, err := r.Recv(); err == nil {
		t.Fatal("Recv returned a truncated body as a frame")
	}
}

// A truncated header returns EOF, as for a normal disconnect.
func TestTruncatedHeaderReportsEOF(t *testing.T) {
	w, r := pipeConns(t)

	go func() {
		_, _ = w.raw.Write([]byte{0, 0})
		w.raw.Close()
	}()

	_, _, err := r.Recv()
	if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		t.Fatalf("error = %v, want an EOF from a short header", err)
	}
}

// The header is a big-endian length covering the type byte and payload.
func TestFrameHeaderLayout(t *testing.T) {
	var buf bytes.Buffer
	c := NewConn(bufConn{buf: &buf})
	c.writeTimeout = 0

	if err := c.Send(MsgPortsAck, &PortsAckPayload{Version: 1}); err != nil {
		t.Fatalf("send: %v", err)
	}
	frame := buf.Bytes()
	if len(frame) < 5 {
		t.Fatalf("frame is %d bytes, shorter than a header", len(frame))
	}
	total := binary.BigEndian.Uint32(frame[:4])
	if int(total) != len(frame)-4 {
		t.Fatalf("length field = %d, want %d (type byte + payload)", total, len(frame)-4)
	}
	if MessageType(frame[4]) != MsgPortsAck {
		t.Fatalf("type byte = %d, want %d", frame[4], MsgPortsAck)
	}
	if !bytes.HasPrefix(frame[5:], []byte(`{`)) {
		t.Fatalf("payload does not start the JSON body: %q", frame[5:])
	}
}

// Pins the message type numbers shared with the edge.
func TestMessageTypeNumbersAreFixed(t *testing.T) {
	for mt, want := range map[MessageType]byte{
		MsgRegister: 1, MsgRegisterAck: 2, MsgNewConnection: 3, MsgConnectionReady: 4,
		MsgHeartbeat: 5, MsgHeartbeatAck: 6, MsgSetActive: 7, MsgShutdown: 8,
		MsgError: 9, MsgRedirect: 10, MsgMuxBind: 11, MsgMuxBindAck: 12,
		MsgPortsUpdate: 13, MsgPortsAck: 14,
	} {
		if byte(mt) != want {
			t.Errorf("%v = %d, want %d", mt, byte(mt), want)
		}
	}
}

// Concurrent senders never interleave frames, and a reader runs alongside
// them.
func TestConcurrentSendersEmitWholeFrames(t *testing.T) {
	w, r := pipeConns(t)

	const senders, each = 8, 25
	var wg sync.WaitGroup
	wg.Add(senders)
	for i := range senders {
		go func() {
			defer wg.Done()
			for j := range each {
				if err := w.Send(MsgPortsAck, &PortsAckPayload{Version: uint64(i*each + j)}); err != nil {
					return
				}
			}
		}()
	}

	seen := make(map[uint64]bool, senders*each)
	for range senders * each {
		if err := r.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("read deadline: %v", err)
		}
		mt, body, err := r.Recv()
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		if mt != MsgPortsAck {
			t.Fatalf("type = %v, want MsgPortsAck: the stream desynced", mt)
		}
		var p PortsAckPayload
		mustJSON(t, body, &p)
		seen[p.Version] = true
	}
	wg.Wait()

	if len(seen) != senders*each {
		t.Fatalf("read %d distinct frames, want %d", len(seen), senders*each)
	}
}

// mustJSON decodes a frame body into v.
func mustJSON(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("unmarshal %T: %v", v, err)
	}
}

// bufConn is a net.Conn that writes into a buffer. Only Write and
// SetWriteDeadline are used.
type bufConn struct {
	net.Conn
	buf *bytes.Buffer
}

func (c bufConn) Write(p []byte) (int, error)    { return c.buf.Write(p) }
func (bufConn) SetWriteDeadline(time.Time) error { return nil }

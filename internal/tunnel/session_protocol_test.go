package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/localport/agent/internal/proto"
	"github.com/localport/agent/internal/transport"
)

// fakeEdge is the edge side of a control connection using the real framing.
type fakeEdge struct {
	conn *proto.Conn
}

func (e *fakeEdge) send(t *testing.T, mt proto.MessageType, payload any) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- e.conn.Send(mt, payload) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("edge send %s: %v", mt, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("edge send %s blocked: the agent is not reading", mt)
	}
}

// expect reads one frame and fails the test if none arrives.
func (e *fakeEdge) expect(t *testing.T, want proto.MessageType) []byte {
	t.Helper()
	if err := e.conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("edge read deadline: %v", err)
	}
	mt, body, err := e.conn.Recv()
	if err != nil {
		t.Fatalf("edge waiting for %s: %v", want, err)
	}
	if mt != want {
		t.Fatalf("agent sent %s, want %s", mt, want)
	}
	return body
}

// connectedTunnel attaches a Tunnel to a fake edge and runs its receive loop.
func connectedTunnel(t *testing.T, opts Options) (*Tunnel, *fakeEdge) {
	t.Helper()
	agentSide, edgeSide := net.Pipe()

	if opts.Token == "" {
		opts.Token = "tok"
	}
	if opts.Edge == "" {
		opts.Edge = "connect.eu.localport.dev:443"
	}
	tn := New(opts)
	tn.mu.Lock()
	tn.raw = agentSide
	tn.conn = proto.NewConn(agentSide)
	tn.mu.Unlock()

	edge := &fakeEdge{conn: proto.NewConn(edgeSide)}
	loop := startReceiveLoop(tn)

	t.Cleanup(func() {
		tn.Stop()
		agentSide.Close()
		edgeSide.Close()
		loop.Wait()
	})
	return tn, edge
}

// recorder captures session events.
type recorder struct {
	mu       sync.Mutex
	errs     []error
	ports    [][]proto.DevicePort
	shutdown []string
	conns    []DataConnInfo
	closed   []string
}

func (r *recorder) OnStateChange(string, State, State) {}
func (r *recorder) OnConnected(string, Info)           {}
func (r *recorder) OnDisconnected(string, error)       {}
func (r *recorder) OnError(_ string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs = append(r.errs, err)
}

func (r *recorder) OnDataConn(_ string, info DataConnInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.conns = append(r.conns, info)
}
func (r *recorder) OnDataClose(_, connID, _, _ string, _, _ int64, _ time.Duration, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = append(r.closed, connID)
	if err != nil {
		r.errs = append(r.errs, err)
	}
}
func (r *recorder) OnHTTPRequest(string, RequestInfo) {}
func (r *recorder) OnRedirect(string, string, string) {}

func (r *recorder) OnShutdownPolicy(_, reason, _ string, _ proto.LimitType, _ bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.shutdown = append(r.shutdown, reason)
}

func (r *recorder) OnPortsUpdate(_ string, ports []proto.DevicePort) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ports = append(r.ports, ports)
}

func (r *recorder) snapshot() ([]error, [][]proto.DevicePort, []string, []DataConnInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]error(nil), r.errs...),
		append([][]proto.DevicePort(nil), r.ports...),
		append([]string(nil), r.shutdown...),
		append([]DataConnInfo(nil), r.conns...)
}

// closedConns returns the IDs of closed connections.
func (r *recorder) closedConns() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.closed...)
}

// The agent answers each edge heartbeat.
func TestHeartbeatIsAnsweredWithTheSenderTimestamp(t *testing.T) {
	_, edge := connectedTunnel(t, Options{Local: "127.0.0.1:1"})

	edge.send(t, proto.MsgHeartbeat, &proto.HeartbeatPayload{Timestamp: 99})

	body := edge.expect(t, proto.MsgHeartbeatAck)
	var ack proto.HeartbeatAckPayload
	if err := json.Unmarshal(body, &ack); err != nil {
		t.Fatalf("heartbeat ack: %v", err)
	}
	if ack.Timestamp != 99 {
		t.Fatalf("ack timestamp = %d, want the 99 the edge sent", ack.Timestamp)
	}
}

// A device acks the version of the port set it applied.
func TestPortsUpdateIsAppliedAndAcked(t *testing.T) {
	rec := &recorder{}
	tn, edge := connectedTunnel(t, Options{
		Kind: proto.KindDevice, Host: "127.0.0.1", Handler: rec,
	})

	edge.send(t, proto.MsgPortsUpdate, &proto.PortsUpdatePayload{
		Version: 7,
		Ports:   []proto.DevicePort{{Port: 502, Protocol: "tcp"}, {Port: 80, Protocol: "http"}},
	})

	body := edge.expect(t, proto.MsgPortsAck)
	var ack proto.PortsAckPayload
	if err := json.Unmarshal(body, &ack); err != nil {
		t.Fatalf("ports ack: %v", err)
	}
	if ack.Version != 7 {
		t.Fatalf("acked version = %d, want 7", ack.Version)
	}
	if got := tn.ports.Version(); got != 7 {
		t.Fatalf("device holds version %d, want 7", got)
	}
	if got := len(tn.ports.List()); got != 2 {
		t.Fatalf("device serves %d ports, want 2", got)
	}

	// The ack is sent before the event is published.
	waitFor(t, func() bool {
		_, ports, _, _ := rec.snapshot()
		return len(ports) > 0
	}, "the applied ports were never published")

	_, ports, _, _ := rec.snapshot()
	if len(ports) != 1 || len(ports[0]) != 2 {
		t.Fatalf("port update events = %v, want one carrying both ports", ports)
	}
}

// A repeated update is acked again without publishing an event.
func TestARepeatedPortsUpdateIsStillAcked(t *testing.T) {
	rec := &recorder{}
	_, edge := connectedTunnel(t, Options{
		Kind: proto.KindDevice, Host: "127.0.0.1", Handler: rec,
	})

	update := &proto.PortsUpdatePayload{
		Version: 3,
		Ports:   []proto.DevicePort{{Port: 8080, Protocol: "http"}},
	}
	edge.send(t, proto.MsgPortsUpdate, update)
	edge.expect(t, proto.MsgPortsAck)
	waitFor(t, func() bool {
		_, ports, _, _ := rec.snapshot()
		return len(ports) == 1
	}, "the first update was never published")

	edge.send(t, proto.MsgPortsUpdate, update)
	body := edge.expect(t, proto.MsgPortsAck)

	var ack proto.PortsAckPayload
	if err := json.Unmarshal(body, &ack); err != nil {
		t.Fatalf("ports ack: %v", err)
	}
	if ack.Version != 3 {
		t.Fatalf("second ack version = %d, want 3", ack.Version)
	}
	if _, ports, _, _ := rec.snapshot(); len(ports) != 1 {
		t.Fatalf("published %d port updates, want 1 for an unchanged set", len(ports))
	}
}

// A non-retryable shutdown ends the tunnel. The edge sends it when a device is
// removed from a fleet.
func TestNonRetryableShutdownStopsTheTunnel(t *testing.T) {
	rec := &recorder{}
	tn, edge := connectedTunnel(t, Options{Local: "127.0.0.1:1", Handler: rec})

	retryable := false
	edge.send(t, proto.MsgShutdown, &proto.ShutdownPayload{
		Reason: "device removed from the fleet", Code: "FL003", Retryable: &retryable,
	})

	waitFor(t, func() bool {
		_, _, shutdowns, _ := rec.snapshot()
		return len(shutdowns) > 0
	}, "the shutdown was never published")

	select {
	case <-tn.shutdown:
	default:
		t.Fatal("a non-retryable shutdown left the tunnel willing to reconnect")
	}
	_, _, shutdowns, _ := rec.snapshot()
	if shutdowns[0] != "device removed from the fleet" {
		t.Fatalf("reason = %q, want the edge's own text", shutdowns[0])
	}
	if te := tn.consumeTerminalError(); te == nil {
		t.Fatal("no terminal error was recorded for a non-retryable shutdown")
	}
}

// A retryable shutdown ends only the session, for example during an edge
// deploy.
func TestRetryableShutdownEndsOnlyTheSession(t *testing.T) {
	tn, edge := connectedTunnel(t, Options{Local: "127.0.0.1:1"})

	retryable := true
	edge.send(t, proto.MsgShutdown, &proto.ShutdownPayload{Reason: "draining", Retryable: &retryable})

	select {
	case <-tn.disconnected:
	case <-time.After(3 * time.Second):
		t.Fatal("a retryable shutdown did not end the session")
	}
	select {
	case <-tn.shutdown:
		t.Fatal("a retryable shutdown stopped the tunnel from reconnecting")
	default:
	}
}

// A shutdown without the retryable field is retryable.
func TestShutdownWithoutARetryableFieldIsRetryable(t *testing.T) {
	tn, edge := connectedTunnel(t, Options{Local: "127.0.0.1:1"})

	edge.send(t, proto.MsgShutdown, &proto.ShutdownPayload{Reason: "edge restart"})

	select {
	case <-tn.disconnected:
	case <-time.After(3 * time.Second):
		t.Fatal("the session did not end")
	}
	select {
	case <-tn.shutdown:
		t.Fatal("an unqualified shutdown stopped the tunnel for good")
	default:
	}
}

// An Error frame is reported and the session continues.
func TestErrorFrameIsReportedWithoutEndingTheSession(t *testing.T) {
	rec := &recorder{}
	tn, edge := connectedTunnel(t, Options{Local: "127.0.0.1:1", Handler: rec})

	edge.send(t, proto.MsgError, &proto.ErrorPayload{Code: "RS001", Message: "no port available"})

	waitFor(t, func() bool {
		errs, _, _, _ := rec.snapshot()
		return len(errs) > 0
	}, "the error frame was never reported")

	errs, _, _, _ := rec.snapshot()
	if got := errs[0].Error(); got != "[RS001] no port available" {
		t.Fatalf("reported %q, want the code and message from the frame", got)
	}
	select {
	case <-tn.disconnected:
		t.Fatal("an error frame ended the session")
	default:
	}
}

// SetActive and HeartbeatAck are accepted as no-ops.
func TestAdvisoryFramesAreAcceptedSilently(t *testing.T) {
	rec := &recorder{}
	tn, edge := connectedTunnel(t, Options{Local: "127.0.0.1:1", Handler: rec})

	edge.send(t, proto.MsgSetActive, map[string]bool{"active": true})
	edge.send(t, proto.MsgHeartbeatAck, &proto.HeartbeatAckPayload{Timestamp: 1})

	// Frames are handled in order, so an answer to this one shows the
	// earlier two were consumed.
	edge.send(t, proto.MsgHeartbeat, &proto.HeartbeatPayload{Timestamp: 5})
	edge.expect(t, proto.MsgHeartbeatAck)

	if errs, _, shutdowns, _ := rec.snapshot(); len(errs) != 0 || len(shutdowns) != 0 {
		t.Fatalf("advisory frames raised errors %v / shutdowns %v", errs, shutdowns)
	}
	select {
	case <-tn.disconnected:
		t.Fatal("an advisory frame ended the session")
	default:
	}
}

// Unknown frame types are ignored.
func TestUnknownFrameTypeIsIgnored(t *testing.T) {
	rec := &recorder{}
	tn, edge := connectedTunnel(t, Options{Local: "127.0.0.1:1", Handler: rec})

	edge.send(t, proto.MessageType(200), map[string]string{"future": "field"})

	edge.send(t, proto.MsgHeartbeat, &proto.HeartbeatPayload{Timestamp: 2})
	edge.expect(t, proto.MsgHeartbeatAck)

	if errs, _, shutdowns, _ := rec.snapshot(); len(errs) != 0 || len(shutdowns) != 0 {
		t.Fatalf("an unknown frame raised errors %v / shutdowns %v", errs, shutdowns)
	}
	select {
	case <-tn.disconnected:
		t.Fatal("an unknown frame ended the session")
	default:
	}
}

// A malformed body is dropped and the session continues.
func TestMalformedPayloadIsDropped(t *testing.T) {
	rec := &recorder{}
	tn, edge := connectedTunnel(t, Options{Kind: proto.KindDevice, Host: "127.0.0.1", Handler: rec})

	edge.send(t, proto.MsgPortsUpdate, "not an object")

	edge.send(t, proto.MsgHeartbeat, &proto.HeartbeatPayload{Timestamp: 3})
	edge.expect(t, proto.MsgHeartbeatAck)

	if _, ports, _, _ := rec.snapshot(); len(ports) != 0 {
		t.Fatalf("a malformed update published ports %v", ports)
	}
	select {
	case <-tn.disconnected:
		t.Fatal("a malformed payload ended the session")
	default:
	}
}

// A NewConnection starts a dial-back that reports its result under the frame's
// connection ID.
func TestNewConnectionIsProxiedUnderItsConnectionID(t *testing.T) {
	rec := &recorder{}
	tn, edge := connectedTunnel(t, Options{Local: "127.0.0.1:1", Protocol: "tcp", Handler: rec})

	edge.send(t, proto.MsgNewConnection, &proto.NewConnectionPayload{
		ConnectionID: "conn-7", RemoteAddr: "203.0.113.4:5555", TargetProtocol: "tcp",
	})

	waitFor(t, func() bool { return len(rec.closedConns()) > 0 }, "the inbound connection was never reported")

	if got := rec.closedConns()[0]; got != "conn-7" {
		t.Fatalf("reported connection %q, want the edge's conn-7", got)
	}
	// The dispatch slot is released however the dial ends.
	waitFor(t, func() bool { return len(tn.dataSlots) == 0 }, "the connection slot was never released")
}

// At the connection limit, a NewConnection is dropped without a reply.
func TestInboundConnectionsAboveTheCeilingAreRefused(t *testing.T) {
	rec := &recorder{}
	tn, edge := connectedTunnel(t, Options{Local: "127.0.0.1:1", Handler: rec})

	// Fill every slot.
	for range maxConcurrentDataConns {
		tn.dataSlots <- struct{}{}
	}

	edge.send(t, proto.MsgNewConnection, &proto.NewConnectionPayload{
		ConnectionID: "conn-over", RemoteAddr: "203.0.113.9:1", TargetProtocol: "tcp",
	})

	waitFor(t, func() bool {
		errs, _, _, _ := rec.snapshot()
		return len(errs) > 0
	}, "an inbound connection over the ceiling was not reported")

	if _, _, _, conns := rec.snapshot(); len(conns) != 0 {
		t.Fatalf("a refused connection was still opened: %v", conns)
	}
}

// waitFor polls cond until it holds, failing with msg on timeout.
func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}

// A dial-back to an unreachable local service reports 502 in
// ConnectionReady, as a mux stream does in its response status.
func TestDialbackReportsAnUnreachableLocalService(t *testing.T) {
	rec := &recorder{}
	tn, edge := connectedTunnel(t, Options{Local: "127.0.0.1:1", Protocol: "tcp", Handler: rec})

	dialer := newRecordingDialer()
	tn.mu.Lock()
	tn.dialer = dialer
	tn.edgeAddr = "edge.test:443"
	tn.mu.Unlock()

	edge.send(t, proto.MsgNewConnection, &proto.NewConnectionPayload{
		ConnectionID: "c-down", RemoteAddr: "203.0.113.4:5555", TargetProtocol: "tcp",
	})

	data := dialer.accept(t)
	defer data.Close()

	mt, body, err := proto.NewConn(data).Recv()
	if err != nil {
		t.Fatalf("waiting for ConnectionReady: %v", err)
	}
	if mt != proto.MsgConnectionReady {
		t.Fatalf("agent sent %s, want ConnectionReady", mt)
	}
	var ready proto.ConnectionReadyPayload
	if err := json.Unmarshal(body, &ready); err != nil {
		t.Fatalf("ConnectionReady payload: %v", err)
	}
	if ready.ConnectionID != "c-down" {
		t.Fatalf("ConnectionReady names %q, want c-down", ready.ConnectionID)
	}
	if ready.Status != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: the edge reads 0 and 200 as accepted", ready.Status)
	}
}

// A reachable local service is reported as accepted and proxied.
func TestDialbackReportsAReachableLocalService(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()

	tn, edge := connectedTunnel(t, Options{Local: ln.Addr().String(), Protocol: "tcp"})
	dialer := newRecordingDialer()
	tn.mu.Lock()
	tn.dialer = dialer
	tn.edgeAddr = "edge.test:443"
	tn.mu.Unlock()

	edge.send(t, proto.MsgNewConnection, &proto.NewConnectionPayload{
		ConnectionID: "c-up", RemoteAddr: "203.0.113.4:5555", TargetProtocol: "tcp",
	})

	data := dialer.accept(t)
	defer data.Close()

	mt, body, err := proto.NewConn(data).Recv()
	if err != nil {
		t.Fatalf("waiting for ConnectionReady: %v", err)
	}
	if mt != proto.MsgConnectionReady {
		t.Fatalf("agent sent %s, want ConnectionReady", mt)
	}
	var ready proto.ConnectionReadyPayload
	if err := json.Unmarshal(body, &ready); err != nil {
		t.Fatalf("ConnectionReady payload: %v", err)
	}
	if ready.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", ready.Status)
	}

	if err := data.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	if _, err := data.Write([]byte("ping")); err != nil {
		t.Fatalf("visitor write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(data, buf); err != nil {
		t.Fatalf("visitor read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echoed %q, want %q", buf, "ping")
	}
}

// recordingDialer replaces the edge transport with in-memory connections.
type recordingDialer struct {
	conns chan net.Conn
}

func newRecordingDialer() *recordingDialer {
	return &recordingDialer{conns: make(chan net.Conn, 4)}
}

func (d *recordingDialer) Kind() transport.Kind { return transport.KindRaw }

func (d *recordingDialer) Dial(context.Context, string, string) (net.Conn, error) {
	agentSide, edgeSide := net.Pipe()
	select {
	case d.conns <- edgeSide:
		return agentSide, nil
	default:
		agentSide.Close()
		edgeSide.Close()
		return nil, errors.New("recordingDialer: no reader for this data connection")
	}
}

// accept returns the edge's end of the next dial-back.
func (d *recordingDialer) accept(t *testing.T) net.Conn {
	t.Helper()
	select {
	case c := <-d.conns:
		return c
	case <-time.After(3 * time.Second):
		t.Fatal("the agent never dialed back")
		return nil
	}
}

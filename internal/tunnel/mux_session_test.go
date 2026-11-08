package tunnel

import (
	"context"
	"net"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/localport/agent/internal/proto"
	"github.com/localport/agent/internal/transport"
)

// ackThenCloseDialer acks every MuxBind and closes the conn once the agent
// reads for HTTP/2. A net.Pipe fails the agent's SetReadDeadline after the far
// end closes, so the close waits until the agent has taken one byte past the
// bind.
type ackThenCloseDialer struct{ binds atomic.Int32 }

func (d *ackThenCloseDialer) Kind() transport.Kind { return transport.KindRaw }

func (d *ackThenCloseDialer) Dial(context.Context, string, string) (net.Conn, error) {
	agentSide, edgeSide := net.Pipe()
	go func() {
		defer edgeSide.Close()
		pc := proto.NewConn(edgeSide)
		if mt, _, err := pc.Recv(); err != nil || mt != proto.MsgMuxBind {
			return
		}
		d.binds.Add(1)
		_ = pc.Send(proto.MsgMuxBindAck, &proto.MuxBindAckPayload{Success: true})
		_, _ = edgeSide.Write([]byte{0})
	}()
	return agentSide, nil
}

// portMuxBackoffs runs the port mux until it has slept n times and returns the
// sleeps. Each call of the clock advances it by step.
func portMuxBackoffs(t *testing.T, n int, step time.Duration) []time.Duration {
	t.Helper()
	d := &ackThenCloseDialer{}
	tn := sessionDeviceTunnel(Options{})
	var clock atomic.Int64
	tn.now = func() time.Time { return time.Unix(0, clock.Add(int64(step))) }
	var slept []time.Duration
	tn.sleep = func(_ context.Context, w time.Duration) bool {
		slept = append(slept, w)
		return len(slept) < n
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		tn.runMux(context.Background(), "connect.eu.localport.dev:443", "s1", d)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runMux did not stop")
	}
	if got := int(d.binds.Load()); got != n {
		t.Fatalf("binds = %d, want %d", got, n)
	}
	return slept
}

// An edge that acks each bind and then drops the conn does not reset the
// backoff.
func TestPortMuxBackoffGrowsWhenBindsDropEarly(t *testing.T) {
	got := portMuxBackoffs(t, 4, 0)
	want := []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second}
	if !slices.Equal(got, want) {
		t.Fatalf("backoffs = %v, want %v", got, want)
	}
}

// A mux that stayed up past the stability window starts the backoff over.
func TestPortMuxBackoffResetsAfterAStableMux(t *testing.T) {
	got := portMuxBackoffs(t, 3, sessionMuxStableAfter)
	want := []time.Duration{500 * time.Millisecond, 500 * time.Millisecond, 500 * time.Millisecond}
	if !slices.Equal(got, want) {
		t.Fatalf("backoffs = %v, want %v", got, want)
	}
}

// An edge that stalls before MuxBindAck holds the port mux's stop no longer
// than the conn close takes, far under muxBindTimeout.
func TestPortMuxStopEndsAStalledBind(t *testing.T) {
	before := runtime.NumGoroutine()
	d := &stallingBindDialer{binds: make(chan struct{}, 1)}
	tn := sessionDeviceTunnel(Options{})
	tn.mu.Lock()
	tn.sessionID, tn.dialer, tn.edgeAddr = "s1", d, "connect.eu.localport.dev:443"
	tn.mu.Unlock()

	stop := tn.startMux(context.Background())
	select {
	case <-d.binds:
	case <-time.After(3 * time.Second):
		t.Fatal("no MuxBind")
	}

	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(muxBindTimeout / 2):
		t.Fatal("stop waited on a bind the edge never answered")
	}
	goroutinesSettle(t, before)
}

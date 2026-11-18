package tunnel

import (
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/localport/agent/internal/proto"
)

// disconnectRecorder is an EventHandler that counts connects and records
// each OnDisconnected cause.
type disconnectRecorder struct {
	handlerFunc
	connects atomic.Int32
	mu       sync.Mutex
	causes   []error
}

func (r *disconnectRecorder) OnConnected(string, Info) { r.connects.Add(1) }

func (r *disconnectRecorder) OnDisconnected(_ string, err error) {
	r.mu.Lock()
	r.causes = append(r.causes, err)
	r.mu.Unlock()
}

func (r *disconnectRecorder) last() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.causes) == 0 {
		return nil
	}
	return r.causes[len(r.causes)-1]
}

// registerThenDrop plays the edge for one session: it accepts the
// registration, waits until the tunnel is active, advances clock by upFor and
// closes the connection.
func registerThenDrop(t *testing.T, r *refusalRun, clock *atomic.Int64, upFor time.Duration) {
	t.Helper()
	h := r.tn.opts.Handler.(*disconnectRecorder)
	before := h.connects.Load()
	edge := r.register(t, proto.RegisterAckPayload{Success: true, SessionID: "s1"})
	for deadline := time.Now().Add(3 * time.Second); h.connects.Load() == before; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the tunnel did not connect")
		}
	}
	clock.Add(int64(upFor))
	_ = edge.conn.Close()
}

// startDropRun is startRefusalRun with a clock the test advances. The test
// ends on an accepted session, which Stop ends at once.
func startDropRun(t *testing.T) (*refusalRun, *atomic.Int64) {
	t.Helper()
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	r := startRefusalRun(t, Options{Kind: proto.KindDevice, DisableMux: true, Handler: &disconnectRecorder{}}, func(tn *Tunnel) {
		tn.now = func() time.Time { return time.Unix(0, clock.Load()) }
	})
	t.Cleanup(func() { r.register(t, proto.RegisterAckPayload{Success: true, SessionID: "s1"}) })
	return r, &clock
}

// baseBackoff is backoffFor(attempt) without its jitter.
func baseBackoff(attempt int) time.Duration {
	return min(time.Duration(float64(time.Second)*math.Pow(1.5, float64(attempt-1))), maxBackoff)
}

// A session that registers and drops at once does not reset the reconnect
// backoff, so an edge that accepts and drops each registration is not
// redialled every second forever.
func TestReconnectBackoffGrowsWhenSessionsDropEarly(t *testing.T) {
	r, clock := startDropRun(t)
	for attempt := 1; attempt <= 4; attempt++ {
		registerThenDrop(t, r, clock, time.Second)
		if d := r.nextWait(t); d < baseBackoff(attempt) {
			t.Fatalf("wait after early drop %d = %v, want at least %v (backoff attempt %d)", attempt, d, baseBackoff(attempt), attempt)
		}
	}
}

// A session that stayed up controlStableAfter starts the backoff over.
func TestReconnectBackoffResetsAfterAStableSession(t *testing.T) {
	r, clock := startDropRun(t)
	for range 2 {
		registerThenDrop(t, r, clock, time.Second)
		r.nextWait(t)
	}
	registerThenDrop(t, r, clock, controlStableAfter)
	if d, ceiling := r.nextWait(t), baseBackoff(1)*5/4; d >= ceiling {
		t.Fatalf("wait after a stable session = %v, want the first backoff (under %v)", d, ceiling)
	}
}

// A session the edge closes reports why it ended, so a log of reconnects
// never shows a disconnect without a cause.
func TestDisconnectReportsTheCause(t *testing.T) {
	r, clock := startDropRun(t)
	registerThenDrop(t, r, clock, time.Second)
	r.nextWait(t)
	cause := r.tn.opts.Handler.(*disconnectRecorder).last()
	if cause == nil {
		t.Fatal("OnDisconnected got no cause for a connection the edge closed")
	}
	t.Logf("cause: %v", cause)
}

// A session the edge kicks with a hinted Shutdown (an admin's Disconnect)
// reports the Shutdown's reason and code as its cause.
func TestKickedSessionReportsTheShutdown(t *testing.T) {
	r, _ := startDropRun(t)
	edge := r.register(t, proto.RegisterAckPayload{Success: true, SessionID: "s1"})
	_ = edge.conn.SetReadDeadline(time.Time{})
	go func() {
		for {
			if _, _, err := edge.conn.Recv(); err != nil {
				return
			}
		}
	}()
	edge.send(t, proto.MsgShutdown, proto.ShutdownPayload{Reason: "disconnected by an admin", Code: "SE040", Retryable: boolPtr(true), RetryAfter: 60})
	r.nextWait(t)
	cause := r.tn.opts.Handler.(*disconnectRecorder).last()
	if cause == nil || !strings.Contains(cause.Error(), "disconnected by an admin [SE040]") {
		t.Fatalf("kicked session cause = %v, want the Shutdown's reason and code", cause)
	}
}

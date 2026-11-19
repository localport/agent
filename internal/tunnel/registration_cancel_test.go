package tunnel

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/proto"
)

// Stop or ctx cancellation ends a Register exchange the edge never answers,
// well before registrationTimeout.
func TestStopOrCancelEndsARegistrationInProgress(t *testing.T) {
	for name, end := range map[string]func(*Tunnel, context.CancelFunc){
		"stop":   func(tn *Tunnel, _ context.CancelFunc) { tn.Stop() },
		"cancel": func(_ *Tunnel, cancel context.CancelFunc) { cancel() },
	} {
		t.Run(name, func(t *testing.T) {
			tn, d := deviceTunnel(t, &fakeCredential{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- tn.Run(ctx) }()

			var edgeSide net.Conn
			select {
			case edgeSide = <-d.edges:
			case <-time.After(3 * time.Second):
				t.Fatal("Run did not dial")
			}
			t.Cleanup(func() { _ = edgeSide.Close() })
			(&fakeEdge{conn: proto.NewConn(edgeSide)}).expect(t, proto.MsgRegister)

			start := time.Now()
			end(tn, cancel)
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatalf("Run still registering %v after the end", time.Since(start))
			}
		})
	}
}

// Stop ends the handling of a refusal that blocks, such as a pending renewal
// the control plane never answers.
func TestStopEndsTheHandlingOfARefusal(t *testing.T) {
	cred := &fakeCredential{presentation: &identity.Presentation{Serial: "aa", Pending: true}, refusedWaits: true}
	tn, d := deviceTunnel(t, cred)
	done := make(chan error, 1)
	go func() { done <- tn.Run(context.Background()) }()

	var edgeSide net.Conn
	select {
	case edgeSide = <-d.edges:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not dial")
	}
	t.Cleanup(func() { _ = edgeSide.Close() })
	edge := &fakeEdge{conn: proto.NewConn(edgeSide)}
	edge.expect(t, proto.MsgRegister)
	edge.send(t, proto.MsgRegisterAck, proto.RegisterAckPayload{Error: "refused", ErrorCode: "SE031", Retryable: boolPtr(false)})
	for {
		if _, refused := cred.counts(); refused > 0 {
			break
		}
		select {
		case <-done:
			t.Fatal("Run returned before the refusal was handled")
		case <-time.After(5 * time.Millisecond):
		}
	}
	tn.Stop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run still handling the refusal 1s after Stop")
	}
}

// A Stop that lands as the RegisterAck arrives stores no session and does not
// mark the certificate registered.
func TestStopRacingTheAckServesNoSession(t *testing.T) {
	cred := &fakeCredential{presentation: &identity.Presentation{}}
	tn, d := deviceTunnel(t, cred)
	t.Cleanup(func() { ackReceived = nil })
	ackReceived = func(xctx context.Context) {
		tn.Stop()
		<-xctx.Done()
	}
	done := make(chan error, 1)
	go func() { done <- tn.Run(context.Background()) }()

	var edgeSide net.Conn
	select {
	case edgeSide = <-d.edges:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not dial")
	}
	t.Cleanup(func() { _ = edgeSide.Close() })
	edge := &fakeEdge{conn: proto.NewConn(edgeSide)}
	edge.expect(t, proto.MsgRegister)
	edge.send(t, proto.MsgRegisterAck, proto.RegisterAckPayload{Success: true, SessionID: "s1"})
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after the Stop")
	}
	tn.mu.RLock()
	raw, session := tn.raw, tn.sessionID
	tn.mu.RUnlock()
	cred.mu.Lock()
	registered := cred.registered
	cred.mu.Unlock()
	if raw != nil || session != "" || registered != 0 {
		t.Fatalf("after a Stop racing the ack: raw %v, session %q, registered %d; want none", raw, session, registered)
	}
}

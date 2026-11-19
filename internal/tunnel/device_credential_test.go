package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/proto"
	"github.com/localport/agent/internal/transport"
)

// fakeCredential records how the tunnel drives a device credential.
type fakeCredential struct {
	mu           sync.Mutex
	presentation *identity.Presentation
	registered   int
	refused      int
	refusedRetry bool
	refusedWaits bool
	due, force   bool
	presentErr   error
}

func (c *fakeCredential) Present() (*identity.Presentation, error) {
	return c.presentation, c.presentErr
}

// A lost pending certificate ends the device with a non-retryable
// RegistrationError carrying the agent's code, before any dial.
func TestPendingLostIsACodedRegistrationError(t *testing.T) {
	tn, _ := deviceTunnel(t, &fakeCredential{presentErr: fmt.Errorf("present: %w", identity.ErrPendingLost)})
	var regErr *RegistrationError
	err := tn.connect(context.Background(), 0)
	if !errors.As(err, &regErr) || regErr.Retryable || regErr.Code != string(identity.ErrPendingLost.Code) || regErr.Message != identity.ErrPendingLost.Msg {
		t.Fatalf("connect = %#v, want a non-retryable RegistrationError with code %s", err, identity.ErrPendingLost.Code)
	}
}

func (c *fakeCredential) Registered(*identity.Presentation) {
	c.mu.Lock()
	c.registered++
	c.mu.Unlock()
}

func (c *fakeCredential) Refused(ctx context.Context, _ *identity.Presentation, _ string) (bool, error) {
	c.mu.Lock()
	c.refused++
	retry, waits := c.refusedRetry, c.refusedWaits
	c.mu.Unlock()
	if waits {
		// A renewal against a control plane that does not answer.
		<-ctx.Done()
		return true, ctx.Err()
	}
	return retry, nil
}

func (c *fakeCredential) Tick(*identity.Presentation, time.Time) (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.due, c.force
}

func (c *fakeCredential) counts() (registered, refused int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.registered, c.refused
}

// pipeDialer hands each dialed connection's edge side to the test.
type pipeDialer struct{ edges chan net.Conn }

func (d *pipeDialer) Kind() transport.Kind { return transport.KindRaw }

func (d *pipeDialer) Dial(context.Context, string, string) (net.Conn, error) {
	agentSide, edgeSide := net.Pipe()
	d.edges <- edgeSide
	return agentSide, nil
}

func deviceTunnel(t *testing.T, cred *fakeCredential) (*Tunnel, *pipeDialer) {
	t.Helper()
	d := &pipeDialer{edges: make(chan net.Conn, 1)}
	tn := New(Options{Kind: proto.KindDevice, Edge: "connect.eu.localport.dev:443", Credential: cred, Capabilities: []string{"terminal"}})
	tn.newDialers = func(transport.Options) []transport.Dialer { return []transport.Dialer{d} }
	t.Cleanup(tn.closeConn)
	return tn, d
}

// connectWithAck runs one connect attempt that the fake edge answers with ack.
func connectWithAck(t *testing.T, tn *Tunnel, d *pipeDialer, ack proto.RegisterAckPayload) error {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- tn.connect(context.Background(), 0) }()
	edgeSide := <-d.edges
	t.Cleanup(func() { edgeSide.Close() })
	edge := &fakeEdge{conn: proto.NewConn(edgeSide)}
	var reg proto.RegisterPayload
	if err := json.Unmarshal(edge.expect(t, proto.MsgRegister), &reg); err != nil {
		t.Fatal(err)
	}
	if reg.Token != "" || len(reg.Capabilities) != 1 {
		t.Fatalf("device Register = %+v, want no token and the capabilities", reg)
	}
	edge.send(t, proto.MsgRegisterAck, ack)
	select {
	case err := <-result:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("connect did not return")
		return nil
	}
}

func boolPtr(b bool) *bool { return &b }

// A refused registration never reaches Registered, which would promote the
// pending certificate; a successful one does, once.
func TestDeviceCredentialIsRegisteredOnlyAfterASuccessfulAck(t *testing.T) {
	cred := &fakeCredential{presentation: &identity.Presentation{Serial: "aa", Pending: true}}
	tn, d := deviceTunnel(t, cred)

	err := connectWithAck(t, tn, d, proto.RegisterAckPayload{Success: false, Error: "unavailable", ErrorCode: "ED001", Retryable: boolPtr(true)})
	if err == nil {
		t.Fatal("a refused registration returned success")
	}
	if registered, _ := cred.counts(); registered != 0 {
		t.Fatalf("Registered ran %d times after a refusal", registered)
	}
	if err := connectWithAck(t, tn, d, proto.RegisterAckPayload{Success: true, SessionID: "s1"}); err != nil {
		t.Fatal(err)
	}
	if registered, _ := cred.counts(); registered != 1 {
		t.Fatalf("Registered ran %d times after a RegisterAck, want 1", registered)
	}
	tn.mu.RLock()
	presented := tn.presented
	tn.mu.RUnlock()
	if presented != cred.presentation {
		t.Fatal("the session does not record the certificate it registered with")
	}
}

// Only a non-retryable refusal is handed to the credential, which may turn it
// into a retry.
func TestOnlyANonRetryableRefusalReachesTheCredential(t *testing.T) {
	cred := &fakeCredential{presentation: &identity.Presentation{Serial: "aa", Pending: true}, refusedRetry: true}
	tn, d := deviceTunnel(t, cred)

	var regErr *RegistrationError
	err := connectWithAck(t, tn, d, proto.RegisterAckPayload{Error: "busy", ErrorCode: "SE031", Retryable: boolPtr(true)})
	if !errors.As(err, &regErr) || !regErr.Retryable {
		t.Fatalf("retryable refusal = %v", err)
	}
	if _, refused := cred.counts(); refused != 0 {
		t.Fatalf("Refused ran %d times for a retryable refusal", refused)
	}
	err = connectWithAck(t, tn, d, proto.RegisterAckPayload{Error: "refused", ErrorCode: "SE031", Retryable: boolPtr(false)})
	if !errors.As(err, &regErr) || !regErr.Retryable {
		t.Fatalf("refusal the credential retries = %v, want retryable", err)
	}
	if _, refused := cred.counts(); refused != 1 {
		t.Fatalf("Refused ran %d times, want 1", refused)
	}
}

// A due rollover waits until no connection and no browser or CLI session is
// open; a forced one does not.
func TestRolloverWaitsForOpenConnectionsUnlessForced(t *testing.T) {
	for _, open := range []string{"connection", "session"} {
		for _, force := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s force=%v", open, force), func(t *testing.T) {
				cred := &fakeCredential{presentation: &identity.Presentation{Serial: "aa"}, due: true, force: force}
				tn, _ := deviceTunnel(t, cred)
				tn.rolloverEvery = 5 * time.Millisecond
				sessionDone := make(chan struct{})
				tn.mu.Lock()
				tn.disconnected = sessionDone
				tn.presented = cred.presentation
				tn.mu.Unlock()
				var closeOpen func()
				if open == "connection" {
					tn.addActiveConn(&activeConn{id: "open"})
					closeOpen = func() { tn.removeActiveConn("open") }
				} else {
					h := newStreamEchoHandler()
					stream, peer := net.Pipe()
					defer peer.Close()
					h.mu.Lock()
					h.live[stream] = make(chan struct{})
					h.mu.Unlock()
					tn.opts.SessionHandler = h
					closeOpen = func() {
						h.mu.Lock()
						delete(h.live, stream)
						h.mu.Unlock()
					}
				}

				go tn.rolloverLoop(sessionDone)
				select {
				case <-sessionDone:
					if !force {
						t.Fatalf("a due rollover ended a session with an open %s", open)
					}
				case <-time.After(100 * time.Millisecond):
					if force {
						t.Fatalf("a forced rollover waited for the open %s", open)
					}
					closeOpen()
					select {
					case <-sessionDone:
					case <-time.After(time.Second):
						t.Fatalf("the rollover did not run once the %s closed", open)
					}
				}
				if !tn.rollover.Load() {
					t.Fatal("the rollover did not mark the reconnect as immediate")
				}
				tn.Stop()
			})
		}
	}
}

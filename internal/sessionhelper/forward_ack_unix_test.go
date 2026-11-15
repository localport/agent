//go:build cgo && (linux || darwin)

package sessionhelper

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/localport/agent/internal/launcher"
)

// unixConnPair returns a connected pair of unix stream sockets.
func unixConnPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	a, b, err := launcher.SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := net.FileConn(a)
	_ = a.Close()
	if err != nil {
		t.Fatal(err)
	}
	cb, err := net.FileConn(b)
	_ = b.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ca.Close(); _ = cb.Close() })
	return ca.(*net.UnixConn), cb.(*net.UnixConn)
}

// The forward server keeps its copy of each passed socket until the agent acks
// that id, so the socket never has only in-flight references (macOS tears such
// a socket down); an ack of no held socket ends the server; closeAll releases
// what is still held.
func TestUnixPeerHoldsAPassedSocketUntilItsAck(t *testing.T) {
	agent, server := unixConnPair(t)
	p := &unixForwardPeer{conn: server}
	dialed, _ := unixConnPair(t)
	if err := p.send(launcher.FwdMsg{Type: launcher.FwdOK, ID: 2}, dialed); err != nil {
		t.Fatal(err)
	}
	if len(p.held) != 1 || p.held[2] == nil {
		t.Fatalf("held %v after the send", p.held)
	}
	// The agent's end still reaches the dialed socket through the passed
	// descriptor; nothing closed it.
	fr := launcher.NewForwardReader(agent)
	if m, err := fr.Read(); err != nil || m.Type != launcher.FwdOK {
		t.Fatalf("read %+v, %v", m, err)
	}
	held := p.held[2]
	if err := p.deliver(launcher.FwdMsg{Type: launcher.FwdAck, ID: 2}); err != nil {
		t.Fatal(err)
	}
	if len(p.held) != 0 || !errors.Is(held.Close(), os.ErrClosed) {
		t.Fatalf("held %v after the ack, or its copy not closed", p.held)
	}
	if err := p.deliver(launcher.FwdMsg{Type: launcher.FwdAck, ID: 2}); err == nil {
		t.Fatal("a second ack of the same id was accepted")
	}
	dialed2, _ := unixConnPair(t)
	if err := p.send(launcher.FwdMsg{Type: launcher.FwdOK, ID: 4}, dialed2); err != nil {
		t.Fatal(err)
	}
	p.closeAll()
	if len(p.held) != 0 {
		t.Fatalf("held %v after closeAll", p.held)
	}
}

// Passed sockets not yet acked count against the dial limit: with
// maxForwardConns held, a dial is refused limit instead of dropped; after
// closeAll a late send closes its socket and holds nothing.
func TestUnixPeerHeldSocketsCountAgainstTheLimit(t *testing.T) {
	agent, server := unixConnPair(t)
	p := &unixForwardPeer{conn: server}
	fr := launcher.NewForwardReader(agent)
	for i := range maxForwardConns {
		dialed, _ := unixConnPair(t)
		if err := p.send(launcher.FwdMsg{Type: launcher.FwdOK, ID: uint32(2 + 2*i)}, dialed); err != nil {
			t.Fatal(err)
		}
		if _, err := fr.Read(); err != nil {
			t.Fatal(err)
		}
	}
	if p.conns() != maxForwardConns {
		t.Fatalf("conns %d, want %d held", p.conns(), maxForwardConns)
	}
	s := &forwardServer{peer: p, log: t.Logf, ctx: ctx(t), nextAccepted: 1, listeners: map[uint32]net.Listener{}}
	var wg sync.WaitGroup
	if err := s.handle(launcher.FwdMsg{Type: launcher.FwdDial, ID: 1000, Network: launcher.FwdTCP, Host: "127.0.0.1", Port: 9}, &wg); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	m, err := fr.Read()
	if err != nil || m.Type != launcher.FwdRefused || m.ID != 1000 || m.Code != launcher.FwdCodeLimit {
		t.Fatalf("answer %+v, %v; want refused limit", m, err)
	}
	p.closeAll()
	late, _ := unixConnPair(t)
	if err := p.send(launcher.FwdMsg{Type: launcher.FwdOK, ID: 2000}, late); !errors.Is(err, net.ErrClosed) || p.conns() != 0 {
		t.Fatalf("send after closeAll: %v, %d held", err, p.conns())
	}
}

// With maxForwardConns passed sockets held, a listener's accept is closed
// unreported and the listener keeps accepting.
func TestUnixPeerHeldSocketsCountAgainstTheAcceptLimit(t *testing.T) {
	agent, server := unixConnPair(t)
	p := &unixForwardPeer{conn: server}
	fr := launcher.NewForwardReader(agent)
	for i := range maxForwardConns {
		dialed, _ := unixConnPair(t)
		if err := p.send(launcher.FwdMsg{Type: launcher.FwdOK, ID: uint32(2 + 2*i)}, dialed); err != nil {
			t.Fatal(err)
		}
		if _, err := fr.Read(); err != nil {
			t.Fatal(err)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &forwardServer{peer: p, log: t.Logf, ctx: ctx(t), nextAccepted: 1, listeners: map[uint32]net.Listener{100: ln}}
	done := make(chan struct{})
	go func() { defer close(done); s.accept(100, ln) }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// The dropped connection reads EOF; nothing was sent to the agent.
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("over the limit the connection read %v, want EOF", err)
	}
	s.mu.Lock()
	delete(s.listeners, 100)
	s.mu.Unlock()
	_ = ln.Close()
	<-done
	_ = agent.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if m, err := fr.Read(); err == nil {
		t.Fatalf("the agent got %+v for a connection over the limit", m)
	}
}

// The agent acks each socket it takes, right after the message that carried
// it.
func TestForwardClientAcksAPassedSocket(t *testing.T) {
	client := forwardPairPeer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	echo(t, ln)
	conn, err := client.c.Dial(ctx(t), launcher.FwdTCP, "127.0.0.1", uint16(ln.Addr().(*net.TCPAddr).Port), "")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	roundTrip(t, conn)
	// The round trip above follows the ack on the same channel order: the
	// server read and applied it before it served anything later.
	if _, _, err := client.c.Listen(ctx(t), launcher.FwdTCP, 0, false, "", func(a launcher.Accepted) { _ = a.Conn.Close() }, nil); err != nil {
		t.Fatal(err)
	}
	client.peer.hmu.Lock()
	n := len(client.peer.held)
	client.peer.hmu.Unlock()
	if n != 0 {
		t.Fatalf("%d passed sockets still held after the agent took them", n)
	}
}

type peerPair struct {
	c    *launcher.ForwardClient
	peer *unixForwardPeer
}

// forwardPairPeer is forwardPair with the server's peer exposed.
func forwardPairPeer(t *testing.T) peerPair {
	t.Helper()
	ours, theirs, err := launcher.SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	nc, err := net.FileConn(theirs)
	_ = theirs.Close()
	if err != nil {
		t.Fatal(err)
	}
	peer := &unixForwardPeer{conn: nc.(*net.UnixConn)}
	done := make(chan error, 1)
	go func() { done <- ServeForwards(peer, t.Logf) }()
	client, err := launcher.NewForwardClient(ours, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		if err := <-done; err != nil {
			t.Errorf("forward server: %v", err)
		}
		_ = nc.Close()
	})
	return peerPair{c: client, peer: peer}
}

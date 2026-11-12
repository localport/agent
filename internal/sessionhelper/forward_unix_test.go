//go:build unix

package sessionhelper

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/localport/agent/internal/launcher"
)

// forwardPair runs the forward server on one end of a socketpair, as the
// helper's child does on descriptor 3, and returns the agent's client.
func forwardPair(t *testing.T) *launcher.ForwardClient {
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
	done := make(chan error, 1)
	go func() { done <- ServeForwardSocket(nc.(*net.UnixConn), t.Logf) }()
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
	return client
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

func echo(t *testing.T, ln net.Listener) {
	t.Helper()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
}

func roundTrip(t *testing.T, c io.ReadWriter) {
	t.Helper()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo %q, %v", buf, err)
	}
}

func TestForwardServerDialPassesSockets(t *testing.T) {
	client := forwardPair(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	echo(t, ln)
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	for range 3 {
		conn, err := client.Dial(ctx(t), launcher.FwdTCP, "127.0.0.1", port, "")
		if err != nil {
			t.Fatal(err)
		}
		roundTrip(t, conn)
		_ = conn.Close()
	}
	// A closed port is refused with its code.
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	cport := uint16(closed.Addr().(*net.TCPAddr).Port)
	_ = closed.Close()
	_, err = client.Dial(ctx(t), launcher.FwdTCP, "127.0.0.1", cport, "")
	var r *launcher.ForwardRefusal
	if !errors.As(err, &r) || r.Code != launcher.FwdCodeConnectionRefused {
		t.Fatalf("dial a closed port: %v, want connection_refused", err)
	}
	// A unix socket dial.
	path := filepath.Join(shortTempDir(t), "s")
	uln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer uln.Close()
	echo(t, uln)
	conn, err := client.Dial(ctx(t), launcher.FwdUnix, "", 0, path)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, conn)
	_ = conn.Close()
}

// TestForwardServerConcurrentDials checks that dials issued at once reach
// the server with increasing ids: an id sent out of order ends the server.
// The target is a unix socket: 320 TCP dials would leave 320 TIME_WAIT
// ports, which exhaust macOS's one global ephemeral range under parallel
// test load.
func TestForwardServerConcurrentDials(t *testing.T) {
	client := forwardPair(t)
	path := filepath.Join(shortTempDir(t), "s")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	echo(t, ln)
	for range 20 {
		var wg sync.WaitGroup
		errs := make(chan error, 16)
		for range 16 {
			wg.Go(func() {
				conn, err := client.Dial(ctx(t), launcher.FwdUnix, "", 0, path)
				if err != nil {
					errs <- err
					return
				}
				_ = conn.Close()
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("concurrent dial: %v", err)
		}
	}
}

// TestForwardServerConcurrentAccepts checks that connections accepted at
// once by several listeners reach the client with increasing ids: an id
// received out of order ends the client.
func TestForwardServerConcurrentAccepts(t *testing.T) {
	client := forwardPair(t)
	const listeners, perListener = 4, 16
	accepted := make(chan struct{}, listeners*perListener)
	var ports []uint16
	for range listeners {
		_, port, err := client.Listen(ctx(t), launcher.FwdTCP, 0, false, "", func(a launcher.Accepted) {
			_ = a.Conn.Close()
			accepted <- struct{}{}
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		ports = append(ports, port)
	}
	var wg sync.WaitGroup
	for _, port := range ports {
		for range perListener {
			wg.Go(func() {
				c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
				if err == nil {
					_, _ = c.Read(make([]byte, 1))
					_ = c.Close()
				}
			})
		}
	}
	for i := range listeners * perListener {
		select {
		case <-accepted:
		case <-client.Done():
			t.Fatalf("the client ended after %d accepted connections", i)
		case <-time.After(5 * time.Second):
			t.Fatalf("%d of %d connections accepted", i, listeners*perListener)
		}
	}
	wg.Wait()
}

// shortTempDir is a directory whose socket paths fit sun_path on macOS.
func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "lpfw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

func TestForwardServerListenLoopback(t *testing.T) {
	client := forwardPair(t)
	accepted := make(chan launcher.Accepted, 1)
	id, port, err := client.Listen(ctx(t), launcher.FwdTCP, 0, false, "", func(a launcher.Accepted) { accepted <- a }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if port == 0 {
		t.Fatal("no bound port for a port 0 listen")
	}
	assertLoopbackOnly(t, int(port))
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	a := <-accepted
	if a.Host != "127.0.0.1" || a.Port == 0 {
		t.Fatalf("origin %s:%d", a.Host, a.Port)
	}
	go func() { _, _ = io.Copy(a.Conn, a.Conn) }()
	roundTrip(t, c)
	_ = a.Conn.Close()
	// A second listen on the bound port is refused address_in_use.
	_, _, err = client.Listen(ctx(t), launcher.FwdTCP, port, false, "", func(a launcher.Accepted) { _ = a.Conn.Close() }, nil)
	var r *launcher.ForwardRefusal
	if !errors.As(err, &r) || r.Code != launcher.FwdCodeAddressInUse {
		t.Fatalf("listen on a bound port: %v, want address_in_use", err)
	}
	client.CloseListener(id)
	deadline := time.Now().Add(2 * time.Second)
	for {
		c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
		if err != nil {
			break
		}
		_ = c.Close()
		if time.Now().After(deadline) {
			t.Fatal("the listener still accepts after CloseListener")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestForwardServerUnixListenMaskAndExistingPath(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "r.sock")
	// The mask RunForwardServer sets; after the directory, which it would
	// strip of its search bit.
	old := syscall.Umask(forwardSocketMask)
	defer syscall.Umask(old)
	client := forwardPair(t)
	id, _, err := client.Listen(ctx(t), launcher.FwdUnix, 0, false, path, func(a launcher.Accepted) { _ = a.Conn.Close() }, nil)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket mode %o, want 600", perm)
	}
	// The same path again is refused path_exists, as StreamLocalBindUnlink no.
	_, _, err = client.Listen(ctx(t), launcher.FwdUnix, 0, false, path, func(a launcher.Accepted) { _ = a.Conn.Close() }, nil)
	var r *launcher.ForwardRefusal
	if !errors.As(err, &r) || r.Code != launcher.FwdCodePathExists {
		t.Fatalf("listen on an existing path: %v, want path_exists", err)
	}
	client.CloseListener(id)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the socket file outlived its listener")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestForwardServerListenerLimit(t *testing.T) {
	client := forwardPair(t)
	for i := range maxForwardListeners + 1 {
		_, _, err := client.Listen(ctx(t), launcher.FwdTCP, 0, false, "", func(a launcher.Accepted) { _ = a.Conn.Close() }, nil)
		var r *launcher.ForwardRefusal
		switch {
		case i < maxForwardListeners && err != nil:
			t.Fatalf("listener %d: %v", i+1, err)
		case i == maxForwardListeners && (!errors.As(err, &r) || r.Code != launcher.FwdCodeLimit):
			t.Fatalf("listener %d: %v, want limit", i+1, err)
		}
	}
}

// TestForwardServerEndClosesListeners checks that the agent closing the
// channel ends the server and removes every socket file.
func TestForwardServerEndClosesListeners(t *testing.T) {
	ours, theirs, err := launcher.SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	nc, _ := net.FileConn(theirs)
	_ = theirs.Close()
	done := make(chan error, 1)
	go func() { done <- ServeForwardSocket(nc.(*net.UnixConn), t.Logf) }()
	client, _ := launcher.NewForwardClient(ours, t.Logf)
	path := filepath.Join(shortTempDir(t), "e.sock")
	closed := make(chan struct{})
	if _, _, err := client.Listen(ctx(t), launcher.FwdUnix, 0, false, path, func(a launcher.Accepted) { _ = a.Conn.Close() }, func() { close(closed) }); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	<-closed
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket file after the server's end: %v", err)
	}
	if _, err := client.Dial(ctx(t), launcher.FwdTCP, "127.0.0.1", 1, ""); !errors.Is(err, launcher.ErrForwardHelperFailed) {
		t.Fatalf("dial after the end: %v", err)
	}
}

// assertLoopbackOnly fails when port accepts on a non-loopback address of
// this host, which a wildcard bind would; a loopback dial cannot tell them
// apart. A host with no such address logs that and checks nothing.
func assertLoopbackOnly(t *testing.T, port int) {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		ip, ok := a.(*net.IPNet)
		if !ok || ip.IP.IsLoopback() || ip.IP.To4() == nil || ip.IP.IsLinkLocalUnicast() {
			continue
		}
		c, err := net.DialTimeout("tcp", net.JoinHostPort(ip.IP.String(), strconv.Itoa(port)), time.Second)
		if err == nil {
			_ = c.Close()
			t.Fatalf("port %d accepts on %s: the listener is not loopback only", port, ip.IP)
		}
		return
	}
	t.Log("no non-loopback IPv4 address on this host: the loopback-only bind is not checked")
}

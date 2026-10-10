package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// brokenResolver fails every lookup like an unreachable nameserver.
func brokenResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("nameserver unreachable")
		},
	}
}

func listen(t *testing.T) (ip, port string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	tcp := ln.Addr().(*net.TCPAddr)
	return tcp.IP.String(), fmt.Sprint(tcp.Port)
}

func freshMemory(t *testing.T) {
	t.Helper()
	prev := lastGood
	lastGood = &addrMemory{byHost: make(map[string]string)}
	t.Cleanup(func() { lastGood = prev })
}

// Nameserver down, edge up. A host that connected before dials the remembered IP.
func TestDialEdgeFallsBackToTheLastVerifiedAddress(t *testing.T) {
	freshMemory(t)
	ip, port := listen(t)
	const host = "connect.eu.localport.test"
	d := &net.Dialer{Timeout: 2 * time.Second, Resolver: brokenResolver()}

	if _, err := dialEdge(context.Background(), d, host, port); err == nil {
		t.Fatal("a failed lookup with nothing remembered connected somewhere")
	}

	lastGood.remember(host, &net.TCPAddr{IP: net.ParseIP(ip)})
	conn, err := dialEdge(context.Background(), d, host, port)
	if err != nil {
		t.Fatalf("lookup failed and a verified address was remembered, but the dial failed: %v", err)
	}
	conn.Close()
}

// An unresponsive nameserver leaves enough of the timeout for the fallback dial.
func TestDialEdgeFallsBackWhenTheNameserverDoesNotAnswer(t *testing.T) {
	freshMemory(t)
	ip, port := listen(t)
	const host = "connect.eu.localport.test"
	silent := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	d := &net.Dialer{Resolver: silent}
	lastGood.remember(host, &net.TCPAddr{IP: net.ParseIP(ip)})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := dialEdge(ctx, d, host, port)
	if err != nil {
		t.Fatalf("the lookup timed out and a verified address was remembered, but the dial failed: %v", err)
	}
	conn.Close()
}

// A resolvable name is dialed fresh and the remembered IP is ignored.
func TestDialEdgePrefersAFreshAnswer(t *testing.T) {
	freshMemory(t)
	_, port := listen(t)
	// nothing listens on the remembered IP, so using it would fail.
	lastGood.remember("localhost", &net.TCPAddr{IP: net.ParseIP("192.0.2.1")})

	conn, err := dialEdge(context.Background(), &net.Dialer{Timeout: 2 * time.Second}, "localhost", port)
	if err != nil {
		t.Fatalf("dial with a working lookup: %v", err)
	}
	conn.Close()
}

// SERVFAIL and timeouts fall back, NXDOMAIN does not.
func TestLookupFailedDistinguishesAnAnswerFromAFailure(t *testing.T) {
	cases := map[string]struct {
		err  error
		want bool
	}{
		"timeout":            {&net.DNSError{Err: "i/o timeout", IsTimeout: true}, true},
		"server failure":     {&net.DNSError{Err: "server misbehaving", IsTemporary: true}, true},
		"wrapped":            {fmt.Errorf("tcp dial: %w", &net.DNSError{Err: "server misbehaving"}), true},
		"no such host":       {&net.DNSError{Err: "no such host", IsNotFound: true}, false},
		"connection refused": {errors.New("connect: connection refused"), false},
	}
	for name, tc := range cases {
		if got := lookupFailed(tc.err); got != tc.want {
			t.Errorf("%s: lookupFailed = %v, want %v", name, got, tc.want)
		}
	}
}

func TestRememberIgnoresIPLiteralHosts(t *testing.T) {
	freshMemory(t)
	lastGood.remember("203.0.113.9", &net.TCPAddr{IP: net.ParseIP("203.0.113.9")})
	if _, ok := lastGood.lookup("203.0.113.9"); ok {
		t.Error("an IP literal host was remembered")
	}
}

// onceResolver answers the first A query with ip and SERVFAILs later ones.
// AAAA queries get an empty answer.
func onceResolver(t *testing.T, ip string) *net.Resolver {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	answered := false
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			end := 12
			for end < n && q[end] != 0 {
				end += int(q[end]) + 1
			}
			end += 5 // the root label, type, class
			if end > n {
				continue
			}
			qtype := uint16(q[end-4])<<8 | uint16(q[end-3])
			resp := append([]byte{}, q[:end]...)
			resp[2], resp[3] = 0x81, 0x80 // a response, recursion available, no error
			resp[6], resp[7] = 0, 0
			resp[8], resp[9], resp[10], resp[11] = 0, 0, 0, 0
			switch {
			case qtype != 1:
			case !answered:
				answered = true
				resp[7] = 1
				resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
				resp = append(resp, net.ParseIP(ip).To4()...)
			default:
				resp[3] = 0x82 // SERVFAIL
			}
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", pc.LocalAddr().String())
		},
	}
}

// The fallback also applies when the first lookup succeeds and DialContext's
// own lookup fails.
func TestDialEdgeFallsBackWhenTheSecondLookupFails(t *testing.T) {
	freshMemory(t)
	ip, port := listen(t)
	const host = "connect.eu.localport.test"
	lastGood.remember(host, &net.TCPAddr{IP: net.ParseIP(ip)})
	d := &net.Dialer{Timeout: 2 * time.Second, Resolver: onceResolver(t, "192.0.2.1")}
	conn, err := dialEdge(context.Background(), d, host, port)
	if err != nil {
		t.Fatalf("the dial's lookup failed after the first one answered, and no fallback was tried: %v", err)
	}
	conn.Close()
}

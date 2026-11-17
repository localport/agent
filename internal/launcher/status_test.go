//go:build linux || darwin

package launcher

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// serveStatus runs s.ServeStatus on a socket in a short temporary directory
// and returns its path.
func serveStatus(t *testing.T, s *Server) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "lp-status-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "status.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	c, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.ServeStatus(c, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("ServeStatus: %v", err)
		}
	})
	return path
}

// readRaw reads what the status endpoint at path writes, without the client's
// ownership check (the test's socket is not root's).
func readRaw(t *testing.T, path string) []byte {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	raw, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func waitFrame(t *testing.T, path string, want []byte) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := readRaw(t, path)
		if bytes.Equal(got, want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("status endpoint = %q, want %q", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The agent account publishes frames; the status endpoint serves the latest
// whole; a second publisher is refused while one is open; the frame is gone
// once the publisher closes; publishing takes no helper slot.
func TestStatusRelay(t *testing.T) {
	client, s := serve(t, uint32(os.Getuid()), nil)
	path := serveStatus(t, s)

	pub, err := client.OpenStatus(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteStatusFrame(pub, []byte(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	waitFrame(t, path, []byte(`{"v":1}`))
	if err := WriteStatusFrame(pub, []byte(`{"v":2}`)); err != nil {
		t.Fatal(err)
	}
	waitFrame(t, path, []byte(`{"v":2}`))
	if n := len(s.slots); n != 0 {
		t.Fatalf("a publisher holds %d helper slots, want 0", n)
	}

	var refused *RefusalError
	second, err := client.OpenStatus(ctx(t))
	if err == nil {
		_ = second.Close()
	}
	if !errors.As(err, &refused) || refused.Code != CodeBusy {
		_ = pub.Close()
		t.Fatalf("second publisher = %v, want %s", err, CodeBusy)
	}

	_ = pub.Close()
	waitFrame(t, path, nil)
	again, err := client.OpenStatus(ctx(t))
	if err != nil {
		t.Fatalf("a publisher after the first closed: %v", err)
	}
	_ = again.Close()
}

// A frame over MaxStatusFrame disconnects the publisher and drops its frame.
func TestStatusRelayRefusesAnOversizedFrame(t *testing.T) {
	client, s := serve(t, uint32(os.Getuid()), nil)
	path := serveStatus(t, s)
	pub, err := client.OpenStatus(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()
	if err := WriteStatusFrame(pub, []byte("ok")); err != nil {
		t.Fatal(err)
	}
	waitFrame(t, path, []byte("ok"))
	hdr := []byte{0, 1, 0, 1} // 65537 bytes
	if _, err := pub.Write(hdr); err != nil {
		t.Fatal(err)
	}
	waitFrame(t, path, nil)
	if err := WriteStatusFrame(io.Discard, make([]byte, MaxStatusFrame+1)); !errors.Is(err, ErrStatusFrame) {
		t.Fatalf("WriteStatusFrame over the cap = %v, want ErrStatusFrame", err)
	}
}

// Only the agent account publishes.
func TestStatusPublisherMustBeTheAgent(t *testing.T) {
	client, _ := serve(t, uint32(os.Getuid())+1, nil)
	if _, err := client.OpenStatus(ctx(t)); err == nil {
		t.Fatal("a peer other than the agent account opened the status publication")
	}
}

// Root, the agent account and members of the agent group read the document;
// anyone else is closed without a byte.
func TestStatusReaderAuthorization(t *testing.T) {
	const agentUID, agentGID = 450, 450
	for _, c := range []struct {
		name  string
		uid   uint32
		gids  []uint32
		reads bool
	}{
		{"root", 0, []uint32{0}, true},
		{"agent account", agentUID, []uint32{agentGID}, true},
		{"agent group member", 501, []uint32{20, agentGID}, true},
		{"other account", 501, []uint32{20, 12}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := &Server{AgentUID: agentUID, AgentGID: agentGID, Log: t.Logf}
			s.peerGroups = func(*net.UnixConn) (uint32, []uint32, error) { return c.uid, c.gids, nil }
			s.status.claim()
			s.status.set([]byte("doc"))
			path := serveStatus(t, s)
			got := readRaw(t, path)
			if want := c.reads; (len(got) > 0) != want {
				t.Fatalf("read %q, want a document: %v", got, want)
			}
		})
	}
}

// At most maxStatusReaders are served at once.
func TestStatusReaderCap(t *testing.T) {
	var r statusRelay
	for range maxStatusReaders {
		if !r.enterReader() {
			t.Fatal("a reader under the cap was refused")
		}
	}
	if r.enterReader() {
		t.Fatal("a reader over the cap was admitted")
	}
	r.leaveReader()
	if !r.enterReader() {
		t.Fatal("a reader after one left was refused")
	}
}

// A reader over the cap is closed at accept without a byte, though it is
// authorized and a document is held.
func TestStatusReaderCapAtAccept(t *testing.T) {
	s := &Server{AgentUID: 450, AgentGID: 450, Log: t.Logf}
	s.peerGroups = func(*net.UnixConn) (uint32, []uint32, error) { return 0, []uint32{0}, nil }
	s.status.claim()
	s.status.set([]byte("doc"))
	path := serveStatus(t, s)
	if got := readRaw(t, path); string(got) != "doc" {
		t.Fatalf("under the cap read %q, want doc", got)
	}
	s.status.readers.Store(maxStatusReaders)
	if got := readRaw(t, path); len(got) != 0 {
		t.Fatalf("over the cap read %q, want nothing", got)
	}
}

// A reader that never reads cannot hold its writer past statusWriteTimeout.
func TestStatusWriteDeadline(t *testing.T) {
	var r statusRelay
	r.claim()
	r.set(bytes.Repeat([]byte("x"), MaxStatusFrame))
	server, client := net.Pipe() // nobody reads client
	defer client.Close()
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- r.writeTo(server) }()
	select {
	case err := <-done:
		if err == nil || time.Since(start) < statusWriteTimeout {
			t.Fatalf("writeTo = %v after %v, want a deadline error after %v", err, time.Since(start), statusWriteTimeout)
		}
	case <-time.After(statusWriteTimeout + 5*time.Second):
		t.Fatal("writeTo blocked past its deadline")
	}
}

// ReadStatus refuses an answer over MaxStatusFrame.
func TestReadStatusRefusesAnOversizedAnswer(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "lp-big-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "status.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	must(t, os.Chmod(path, 0o660))
	prevPath, prevIDs := statusSocket, statusTrustedIDs
	gid := socketGroup(t)
	statusSocket = path
	statusTrustedIDs = func() (uint32, uint32, error) { return uint32(os.Getuid()), gid, nil }
	t.Cleanup(func() { statusSocket, statusTrustedIDs = prevPath, prevIDs })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write(make([]byte, MaxStatusFrame+1))
	}()
	if _, err := ReadStatus(ctx(t)); !errors.Is(err, ErrStatusFrame) {
		t.Fatalf("ReadStatus of %d bytes = %v, want ErrStatusFrame", MaxStatusFrame+1, err)
	}
}

// checkStatusSocket accepts only a socket, not a link, of the trusted owner
// and agent group with mode 0660 or narrower, in a directory of the trusted
// owner that group and others cannot write.
func TestStatusClientTrust(t *testing.T) {
	// A socket takes its directory's group on macOS, so the trusted group is
	// read from one made the same way.
	uid, gid := uint32(os.Getuid()), socketGroup(t)
	prev := statusTrustedIDs
	statusTrustedIDs = func() (uint32, uint32, error) { return uid, gid, nil }
	t.Cleanup(func() { statusTrustedIDs = prev })

	setup := func(t *testing.T) (dir, path string) {
		dir, err := os.MkdirTemp("/tmp", "lp-trust-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		path = filepath.Join(dir, "status.sock")
		ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		ln.SetUnlinkOnClose(false)
		t.Cleanup(func() { ln.Close() })
		if err := os.Chmod(path, 0o660); err != nil {
			t.Fatal(err)
		}
		return dir, path
	}

	_, path := setup(t)
	if err := checkStatusSocket(path); err != nil {
		t.Fatalf("a trusted socket was refused: %v", err)
	}
	for name, spoil := range map[string]func(t *testing.T, dir, path string) string{
		"mode wider than 0660": func(t *testing.T, _, path string) string { must(t, os.Chmod(path, 0o666)); return path },
		"another group": func(t *testing.T, _, path string) string {
			statusTrustedIDs = func() (uint32, uint32, error) { return uid, gid + 1, nil }
			t.Cleanup(func() { statusTrustedIDs = func() (uint32, uint32, error) { return uid, gid, nil } })
			return path
		},
		"another owner": func(t *testing.T, _, path string) string {
			statusTrustedIDs = func() (uint32, uint32, error) { return uid + 1, gid, nil }
			t.Cleanup(func() { statusTrustedIDs = func() (uint32, uint32, error) { return uid, gid, nil } })
			return path
		},
		"a link": func(t *testing.T, dir, path string) string {
			link := filepath.Join(dir, "link.sock")
			must(t, os.Symlink(path, link))
			return link
		},
		"not a socket": func(t *testing.T, dir, _ string) string {
			file := filepath.Join(dir, "file.sock")
			must(t, os.WriteFile(file, nil, 0o660))
			return file
		},
		"group-writable directory": func(t *testing.T, dir, path string) string { must(t, os.Chmod(dir, 0o775)); return path },
	} {
		t.Run(name, func(t *testing.T) {
			dir, path := setup(t)
			if err := checkStatusSocket(spoil(t, dir, path)); !errors.Is(err, ErrStatusUntrusted) {
				t.Fatalf("checkStatusSocket = %v, want ErrStatusUntrusted", err)
			}
		})
	}
}

// socketGroup is the group a socket made under /tmp gets.
func socketGroup(t *testing.T) uint32 {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "lp-gid-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Gid
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

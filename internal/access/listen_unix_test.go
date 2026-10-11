//go:build !windows

package access

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestParseForwardSocket(t *testing.T) {
	got, err := ParseForward("unix:/run/user/1000/plc:1.sock:502", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Socket || got.LocalAddr != "/run/user/1000/plc:1.sock" || got.RemotePort != 502 {
		t.Fatalf("got %+v, want the socket path before the last colon and port 502", got)
	}
	for _, bad := range []string{"unix:", "unix:/tmp/a.sock", "unix::502", "unix:/tmp/a.sock:0", "unix:/tmp/a.sock:http"} {
		if _, err := ParseForward(bad, "127.0.0.1"); err == nil {
			t.Errorf("ParseForward(%q) accepted a bad value", bad)
		}
	}
}

// The socket mode is the only access control on the forward, so it must be
// 0600 from bind.
func TestListenSocketIsOwnerOnly(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "f.sock")
	ln, err := listenSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("socket mode = %#o, want no access for group or other", perm)
	}
}

// A stale socket is replaced. A live socket or a regular file is refused and
// left intact.
func TestListenSocketHandlesWhatIsAlreadyThere(t *testing.T) {
	dir := shortTempDir(t)

	stale := filepath.Join(dir, "stale.sock")
	first, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	first.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = first.Close()
	ln, err := listenSocket(stale)
	if err != nil {
		t.Fatalf("a stale socket was not replaced: %v", err)
	}
	defer ln.Close()

	if _, err := listenSocket(stale); err == nil {
		t.Fatal("a socket in use was taken over")
	}

	file := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(file, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenSocket(file); err == nil {
		t.Fatal("a regular file was replaced by a socket")
	}
	if kept, _ := os.ReadFile(file); string(kept) != "keep" {
		t.Fatal("the regular file was changed")
	}
}

// shortTempDir returns a short temporary directory. sun_path holds about 104
// bytes and t.TempDir exceeds it on some systems.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "lp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

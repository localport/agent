package sessionhelper

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/pkg/sftp"

	"github.com/localport/agent/internal/launcher"
)

// filesHarness serves dir over an in-memory connection to a client and
// collects the events the server writes.
type filesHarness struct {
	dir    string
	client *sftp.Client
	events *eventSink
	done   chan error
}

type eventSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (e *eventSink) Write(p []byte) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.buf.Write(p)
}

// list decodes every event frame written so far.
func (e *eventSink) list(t *testing.T) []launcher.FileEvent {
	t.Helper()
	e.mu.Lock()
	raw := bytes.Clone(e.buf.Bytes())
	e.mu.Unlock()
	fr := launcher.NewFrameReader(bytes.NewReader(raw))
	var out []launcher.FileEvent
	for {
		f, err := fr.ReadFrame()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil || f.Type != launcher.FrameEvent {
			t.Fatalf("event frame %+v: %v", f, err)
		}
		ev, err := launcher.ParseFileEvent(f.Data)
		if err != nil {
			t.Fatalf("event %s: %v", f.Data, err)
		}
		out = append(out, ev)
	}
}

func newFilesHarness(t *testing.T) *filesHarness {
	t.Helper()
	base := t.TempDir()
	dir := filepath.Join(base, "root")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "secret"), []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	serverSide, clientSide := net.Pipe()
	h := &filesHarness{dir: dir, events: &eventSink{}, done: make(chan error, 1)}
	go func() { h.done <- ServeFiles(serverSide, dir, h.events) }()
	c, err := sftp.NewClientPipe(clientSide, clientSide)
	if err != nil {
		t.Fatal(err)
	}
	h.client = c
	t.Cleanup(func() {
		_ = c.Close()
		_ = clientSide.Close()
		<-h.done
	})
	return h
}

// Put, get, a write at an offset past the end (resume), and a rewrite in
// place keep the file's identity and bytes; each handle writes one event
// with its byte count.
func TestFilesPutGetAndWritesInPlace(t *testing.T) {
	h := newFilesHarness(t)
	f, err := h.client.Create("/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("hello ")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(filepath.Join(h.dir, "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	f, err = h.client.OpenFile("/a.txt", os.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("world"), 6); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(filepath.Join(h.dir, "a.txt"))
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("the file was replaced: %v", err)
	}
	r, err := h.client.Open("/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil || string(got) != "hello world" {
		t.Fatalf("read %q, %v", got, err)
	}
	want := []launcher.FileEvent{
		{Op: launcher.OpWrite, Path: "/a.txt", Bytes: 6, Result: launcher.ResultOK},
		{Op: launcher.OpWrite, Path: "/a.txt", Bytes: 5, Result: launcher.ResultOK},
		{Op: launcher.OpRead, Path: "/a.txt", Bytes: 11, Result: launcher.ResultOK},
	}
	if got := h.events.list(t); !slices.Equal(got, want) {
		t.Fatalf("events %+v, want %+v", got, want)
	}
}

// Rename never replaces a target (SFTP v3); posix-rename does. mkdir, rmdir
// and remove refuse the other kind. Each operation writes its event.
func TestFilesCommands(t *testing.T) {
	h := newFilesHarness(t)
	for _, name := range []string{"one", "two"} {
		if err := os.WriteFile(filepath.Join(h.dir, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.client.Rename("/one", "/two"); err == nil {
		t.Fatal("rename replaced an existing target")
	}
	// A symlink is not a regular file: it takes the checked rename path.
	if err := os.Symlink("one", filepath.Join(h.dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := h.client.Rename("/link", "/two"); err == nil {
		t.Fatal("rename of a symlink replaced an existing target")
	}
	if err := os.Remove(filepath.Join(h.dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := h.client.Rename("/one", "/three"); err != nil {
		t.Fatal(err)
	}
	if err := h.client.PosixRename("/three", "/two"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(h.dir, "two")); string(b) != "one" {
		t.Fatalf("posix-rename left %q", b)
	}
	if err := h.client.Mkdir("/d"); err != nil {
		t.Fatal(err)
	}
	if err := h.client.RemoveDirectory("/two"); err == nil {
		t.Fatal("rmdir deleted a file")
	}
	// The client's Remove falls back to rmdir when the server refuses to
	// remove a directory; the events show the server's own answers.
	if err := h.client.Remove("/d"); err != nil {
		t.Fatal(err)
	}
	if err := h.client.Remove("/two"); err != nil {
		t.Fatal(err)
	}
	ops := []string{}
	for _, ev := range h.events.list(t) {
		ops = append(ops, ev.Op+":"+ev.Result)
	}
	want := []string{"rename:file_exists", "rename:file_exists", "rename:ok", "rename:ok", "mkdir:ok", "rmdir:failure", "remove:failure",
		"rmdir:ok", "remove:ok"}
	if !slices.Equal(ops, want) {
		t.Fatalf("events %v, want %v", ops, want)
	}
}

// Nothing outside the root is reachable: "..", an absolute path, a symlink
// pointing out (followed directly and with a trailing slash), and a listing
// of the root's parent all fail; the client sees the root as "/".
func TestFilesConfinement(t *testing.T) {
	h := newFilesHarness(t)
	if err := os.Symlink(filepath.Join(filepath.Dir(h.dir), "secret"), filepath.Join(h.dir, "out")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..", filepath.Join(h.dir, "up")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/../secret", "../secret", "/out", "/up/secret", "/up/", "/out/"} {
		if r, err := h.client.Open(p); err == nil {
			b, _ := io.ReadAll(r)
			_ = r.Close()
			t.Fatalf("open %s reached %q", p, b)
		}
	}
	if entries, err := h.client.ReadDir("/up"); err == nil {
		t.Fatalf("listing the root's parent through a symlink: %v", entries)
	}
	if entries, err := h.client.ReadDir("/.."); err != nil || len(entries) != 2 {
		t.Fatalf("/.. lists %v, %v; want the root (out, up)", entries, err)
	}
	if wd, err := h.client.Getwd(); err != nil || wd != "/" {
		t.Fatalf("working directory %q, %v", wd, err)
	}
}

// A directory cannot be opened as a file.
func TestFilesRefusesADirectoryAsAFile(t *testing.T) {
	h := newFilesHarness(t)
	if err := os.Mkdir(filepath.Join(h.dir, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.Open("/dir"); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("open /dir: %v, want permission denied", err)
	}
}

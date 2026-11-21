package sessionhelper

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
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
	return newFilesHarnessWith(t, FilesAccess{Download: true, Upload: true})
}

// newFilesHarnessWith serves a temporary root with access.
func newFilesHarnessWith(t *testing.T, access FilesAccess) *filesHarness {
	t.Helper()
	base := t.TempDir()
	dir := filepath.Join(base, "root")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "secret"), []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	return serveFilesHarness(t, dir, dir, "", access)
}

// newHomeFilesHarness serves the whole file system as the test's user with
// home, a new directory, as the start of relative paths; dir is that home.
func newHomeFilesHarness(t *testing.T) *filesHarness {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatal(err)
	}
	return serveFilesHarness(t, home, "", home, FilesAccess{Download: true, Upload: true})
}

// serveFilesHarness runs ServeFiles with root and home over a pipe to a client.
func serveFilesHarness(t *testing.T, dir, root, home string, access FilesAccess) *filesHarness {
	t.Helper()
	serverSide, clientSide := net.Pipe()
	h := &filesHarness{dir: dir, events: &eventSink{}, done: make(chan error, 1)}
	go func() { h.done <- ServeFiles(serverSide, root, home, access, h.events) }()
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

// A relative link target keeps the client's text and works inside the root;
// an absolute or escaping target gives the client no way out.
func TestFilesSymlinkTargetsAreConfined(t *testing.T) {
	h := newFilesHarness(t)
	if err := os.WriteFile(filepath.Join(h.dir, "inside"), []byte("in"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := h.client.Symlink("inside", "/rel"); err != nil {
		t.Fatalf("relative target: %v", err)
	}
	if got, err := os.Readlink(filepath.Join(h.dir, "rel")); err != nil || got != "inside" {
		t.Fatalf("stored target %q, %v", got, err)
	}
	f, err := h.client.Open("/rel")
	if err != nil {
		t.Fatalf("open through the relative link: %v", err)
	}
	_ = f.Close()
	for name, target := range map[string]string{"/abs": filepath.Join(filepath.Dir(h.dir), "secret"), "/esc": "../secret"} {
		if err := h.client.Symlink(target, name); err != nil {
			continue // refused at creation
		}
		if f, err := h.client.Open(name); err == nil {
			_ = f.Close()
			t.Fatalf("%s to %s reached outside the root", name, target)
		}
	}
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

// A file whose name an event cannot carry as is (a control byte here; macOS
// refuses invalid UTF-8 names, Linux takes both) is still logged, escaped.
func TestFilesLogsANameThatNeedsEscaping(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows refuses control characters in file names")
	}
	h := newFilesHarness(t)
	f, err := h.client.Create("/\x01.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	want := []launcher.FileEvent{{Op: launcher.OpWrite, Path: `/\x01.bin`, Bytes: 1, Result: launcher.ResultOK}}
	if got := h.events.list(t); !slices.Equal(got, want) {
		t.Fatalf("events %+v, want %+v", got, want)
	}
}

// A symlink with an empty target is refused before anything is created, and
// the server keeps serving.
func TestFilesRefusesAnEmptySymlinkTarget(t *testing.T) {
	h := newFilesHarness(t)
	if err := h.client.Symlink("", "/link"); err == nil {
		t.Fatal("an empty symlink target accepted")
	}
	if err := h.client.Mkdir("/after"); err != nil {
		t.Fatalf("the server stopped serving: %v", err)
	}
	want := []launcher.FileEvent{{Op: launcher.OpMkdir, Path: "/after", Result: launcher.ResultOK}}
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

// isDenied reports whether err is the SFTP permission-denied status, which
// the client returns as os.ErrPermission.
func isDenied(err error) bool {
	return errors.Is(err, os.ErrPermission)
}

// deniedFS refuses opens and directory creation with a permission error
// that is not a POSIX errno, as Windows ERROR_ACCESS_DENIED is not.
type deniedFS struct{ filesFS }

func (deniedFS) OpenFile(name string, _ int, _ fs.FileMode) (*os.File, error) {
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
}

func (deniedFS) Mkdir(name string, _ fs.FileMode) error {
	return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrPermission}
}

// A permission refusal of any OS reaches the client as permission denied and
// is logged with that result.
func TestFilesAnswersEveryPermissionRefusalDenied(t *testing.T) {
	dir := t.TempDir()
	events := &eventSink{}
	s := &filesServer{access: FilesAccess{Download: true, Upload: true}, events: events, start: "/", fs: deniedFS{osFS{}}}
	serverSide, clientSide := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- serveSFTP(serverSide, s) }()
	c, err := sftp.NewClientPipe(clientSide, clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Open(filepath.ToSlash(filepath.Join(dir, "a"))); !isDenied(err) {
		t.Errorf("open: %v, want permission denied", err)
	}
	if err := c.Mkdir(filepath.ToSlash(filepath.Join(dir, "d"))); !isDenied(err) {
		t.Errorf("mkdir: %v, want permission denied", err)
	}
	_ = c.Close()
	_ = clientSide.Close()
	<-done
	for _, ev := range events.list(t) {
		if ev.Result != "permission_denied" {
			t.Errorf("event %+v, want result permission_denied", ev)
		}
	}
}

// Without Upload the server behaves as sftp-server -R: every request that
// changes the file system is refused permission denied and logged with that
// result, and nothing changes; listing and stat still work. Without Download
// a read open is refused the same way, and a read-write open needs both.
func TestFilesAccess(t *testing.T) {
	seed := func(h *filesHarness) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(h.dir, "a"), []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(h.dir, "d"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writes := map[string]func(c *sftp.Client) error{
		"create": func(c *sftp.Client) error { _, err := c.Create("/new"); return err },
		"open for write": func(c *sftp.Client) error {
			_, err := c.OpenFile("/a", os.O_WRONLY)
			return err
		},
		"rename":       func(c *sftp.Client) error { return c.Rename("/a", "/b") },
		"posix-rename": func(c *sftp.Client) error { return c.PosixRename("/a", "/b") },
		"remove":       func(c *sftp.Client) error { return c.Remove("/a") },
		"mkdir":        func(c *sftp.Client) error { return c.Mkdir("/e") },
		"rmdir":        func(c *sftp.Client) error { return c.RemoveDirectory("/d") },
		"chmod":        func(c *sftp.Client) error { return c.Chmod("/a", 0o600) },
		"symlink":      func(c *sftp.Client) error { return c.Symlink("a", "/l") },
		"link":         func(c *sftp.Client) error { return c.Link("/a", "/h") },
	}

	t.Run("download only", func(t *testing.T) {
		h := newFilesHarnessWith(t, FilesAccess{Download: true})
		seed(h)
		for name, op := range writes {
			if err := op(h.client); !isDenied(err) {
				t.Fatalf("%s without upload: %v, want permission denied", name, err)
			}
		}
		if _, err := os.Stat(filepath.Join(h.dir, "a")); err != nil {
			t.Fatalf("a refused write changed the file: %v", err)
		}
		if entries, err := os.ReadDir(h.dir); err != nil || len(entries) != 2 {
			t.Fatalf("a refused write changed the root: %v %v", entries, err)
		}
		if _, err := h.client.OpenFile("/a", os.O_RDWR); !isDenied(err) {
			t.Fatalf("read-write open without upload: %v", err)
		}
		f, err := h.client.Open("/a")
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil || string(b) != "data" {
			t.Fatalf("download: %q %v", b, err)
		}
		if _, err := h.client.ReadDir("/"); err != nil {
			t.Fatalf("listing: %v", err)
		}
		denied := 0
		for _, ev := range h.events.list(t) {
			if ev.Result == "permission_denied" {
				denied++
			}
		}
		// Each write, the read-write open, and the rmdir the client's Remove
		// falls back to after its refused remove.
		if want := len(writes) + 2; denied != want {
			t.Fatalf("%d permission_denied events, want %d", denied, want)
		}
	})

	t.Run("upload only", func(t *testing.T) {
		h := newFilesHarnessWith(t, FilesAccess{Upload: true})
		seed(h)
		if _, err := h.client.Open("/a"); !isDenied(err) {
			t.Fatalf("read open without download: %v, want permission denied", err)
		}
		if _, err := h.client.OpenFile("/a", os.O_RDWR); !isDenied(err) {
			t.Fatalf("read-write open without download: %v, want permission denied", err)
		}
		// Write-only, as OpenSSH sftp put and scp open (the client's Create
		// opens read-write, which needs download too).
		f, err := h.client.OpenFile("/new", os.O_WRONLY|os.O_CREATE|os.O_EXCL)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte("up")); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		if b, _ := os.ReadFile(filepath.Join(h.dir, "new")); string(b) != "up" {
			t.Fatalf("upload wrote %q", b)
		}
		if err := h.client.PosixRename("/new", "/a"); err != nil {
			t.Fatalf("posix-rename with upload: %v", err)
		}
		if _, err := h.client.Stat("/a"); err != nil {
			t.Fatalf("stat: %v", err)
		}
	})

	t.Run("none", func(t *testing.T) {
		h := newFilesHarnessWith(t, FilesAccess{})
		seed(h)
		if _, err := h.client.Open("/a"); !isDenied(err) {
			t.Fatalf("read open: %v", err)
		}
		if err := h.client.Mkdir("/e"); !isDenied(err) {
			t.Fatalf("mkdir: %v", err)
		}
		if entries, err := h.client.ReadDir("/"); err != nil || len(entries) != 2 {
			t.Fatalf("listing with no access: %v %v", entries, err)
		}
	})
}

// The access argument has exactly four spellings.
func TestParseFilesAccess(t *testing.T) {
	for _, a := range []FilesAccess{{}, {Download: true}, {Upload: true}, {Download: true, Upload: true}} {
		if got, ok := ParseFilesAccess(a.Arg()); !ok || got != a {
			t.Fatalf("%+v: %+v %v", a, got, ok)
		}
	}
	for _, bad := range []string{"", "upload,download", "read", "Download", "download, upload"} {
		if _, ok := ParseFilesAccess(bad); ok {
			t.Fatalf("%q parsed", bad)
		}
	}
}

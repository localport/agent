//go:build unix

package sessionhelper

import (
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
)

// Without files_root, "." is the login's home with its symlinks resolved,
// and relative names (as scp and sftp send them) resolve there.
func TestFilesWithoutRootStartsAtHome(t *testing.T) {
	h := newHomeFilesHarness(t)
	want, err := filepath.EvalSymlinks(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := h.client.RealPath("."); err != nil || got != want {
		t.Fatalf("realpath . = %q, %v, want %q", got, err, want)
	}
	if err := os.WriteFile(filepath.Join(h.dir, "a.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := h.client.Open("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil || string(got) != "hi" {
		t.Fatalf("read a.txt = %q, %v", got, err)
	}
	w, err := h.client.Create("b.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "b.txt")); err != nil {
		t.Fatalf("a relative create missed the home: %v", err)
	}
}

// Without files_root, "/" is the real root and an absolute symlink is
// followed as the OS follows it.
func TestFilesWithoutRootServesTheWholeFileSystem(t *testing.T) {
	h := newHomeFilesHarness(t)
	entries, err := h.client.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	osEntries, err := os.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, e := range osEntries {
		want = append(want, e.Name())
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("list / = %v, want %v", got, want)
	}
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(h.dir, "abs")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if target, err := h.client.ReadLink(link); err != nil || target != outside {
		t.Fatalf("readlink = %q, %v, want %q", target, err, outside)
	}
	f, err := h.client.Open(link)
	if err != nil {
		t.Fatalf("open through an absolute link: %v", err)
	}
	b, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil || string(b) != "outside" {
		t.Fatalf("read through the link = %q, %v", b, err)
	}
}

// The OS permissions of the login decide; a refusal is permission denied.
func TestFilesWithoutRootKeepsOSPermissions(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	h := newHomeFilesHarness(t)
	locked := filepath.Join(h.dir, "locked")
	if err := os.Mkdir(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	if _, err := h.client.ReadDir(locked); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("list a 000 directory: %v, want permission denied", err)
	}
	if ev := h.events.list(t); len(ev) != 1 || ev[0].Result != "permission_denied" {
		t.Fatalf("events %+v, want one permission_denied", ev)
	}
}

// SFTP v3 rename refuses an existing target; posix-rename replaces it.
func TestFilesWithoutRootRenames(t *testing.T) {
	h := newHomeFilesHarness(t)
	for _, d := range []string{"from", "to"} {
		if err := os.Mkdir(filepath.Join(h.dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.client.Rename("from", "to"); err == nil {
		t.Fatal("rename replaced an existing directory")
	}
	if _, err := os.Stat(filepath.Join(h.dir, "from")); err != nil {
		t.Fatalf("a refused rename moved the source: %v", err)
	}
	if err := h.client.Rename("from", "moved"); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(h.dir, f), []byte(f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.client.PosixRename("a", "b"); err != nil {
		t.Fatalf("posix-rename over a file: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(h.dir, "b")); string(b) != "a" {
		t.Fatalf("posix-rename left %q", b)
	}
	var results []string
	for _, ev := range h.events.list(t) {
		results = append(results, ev.Op+":"+ev.Result)
	}
	if want := []string{"rename:file_exists", "rename:ok", "rename:ok"}; !slices.Equal(results, want) {
		t.Fatalf("events %v, want %v", results, want)
	}
}

// A missing home, or one that is not a directory, refuses the session before
// it is served, both at the helper (filesHome) and in the server (startDir).
func TestFilesRefusesABadHome(t *testing.T) {
	base := t.TempDir()
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, home := range []string{"", filepath.Join(base, "missing"), file} {
		if _, err := filesHome("", home); err == nil {
			t.Errorf("filesHome(%q) accepted it", home)
		}
		if _, err := startDir(home); err == nil {
			t.Errorf("startDir(%q) accepted it", home)
		}
		server, client := net.Pipe()
		err := ServeFiles(server, "", home, false, FilesAccess{}, io.Discard)
		_ = client.Close()
		if err == nil {
			t.Errorf("ServeFiles with home %q served", home)
		}
	}
	if _, err := filesHome("", file); !errors.Is(err, syscall.ENOTDIR) {
		t.Errorf("filesHome(file) = %v, want ENOTDIR", err)
	}
	if got, err := filesHome(base, ""); err != nil || got != "" {
		t.Errorf("filesHome with a root = %q, %v, want empty", got, err)
	}
}

package sessionhelper

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A name that is not valid UTF-8 is served byte for byte.
func TestFilesServesAnInvalidUTF8Name(t *testing.T) {
	h := newFilesHarness(t)
	name := "bad\xffname"
	if err := os.WriteFile(filepath.Join(h.dir, name), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := h.client.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != name {
		t.Fatalf("listing %v", entries)
	}
	f, err := h.client.Open("/" + name)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_ = f.Close()
}

// statvfs reports the file system's own fragment size and name limit.
func TestStatVFSReportsFrsizeAndNamelen(t *testing.T) {
	dir := t.TempDir()
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		t.Fatal(err)
	}
	got, err := statVFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Frsize != uint64(st.Frsize) || got.Namemax != uint64(st.Namelen) {
		t.Fatalf("frsize %d namemax %d, want %d, %d", got.Frsize, got.Namemax, st.Frsize, st.Namelen)
	}
}

// renameNoReplace never replaces a target, whichever of a racing create and
// the rename lands first.
func TestRenameNoReplaceDoesNotReplaceARacingCreate(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for i := range 200 {
		if err := os.Mkdir(filepath.Join(dir, "from"), 0o755); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var renameErr error
		created := false
		wg.Go(func() { renameErr = renameNoReplace(root, "from", "to") })
		wg.Go(func() { created = os.Mkdir(filepath.Join(dir, "to"), 0o700) == nil })
		wg.Wait()
		info, statErr := os.Stat(filepath.Join(dir, "to"))
		if statErr != nil {
			t.Fatal(statErr)
		}
		if created && renameErr == nil {
			t.Fatalf("round %d: a racing create was replaced (mode %v)", i, info.Mode())
		}
		if created && !errors.Is(renameErr, fs.ErrExist) {
			t.Fatalf("round %d: rename over a created target = %v", i, renameErr)
		}
		_ = os.RemoveAll(filepath.Join(dir, "from"))
		_ = os.RemoveAll(filepath.Join(dir, "to"))
	}
}

// A FIFO named as the target's parent is refused at once.
func TestRenameNoReplaceDoesNotBlockOnAFIFOParent(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(dir, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- renameNoReplace(root, "d", "fifo/x") }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a rename under a FIFO succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the rename blocked on the FIFO")
	}
}

// A rename stays inside the root.
func TestRenameNoReplaceIsConfined(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "root")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(base, filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := renameNoReplace(root, "d", "out/escaped"); err == nil {
		t.Fatal("a rename through a symlink out of the root succeeded")
	}
	if _, err := os.Stat(filepath.Join(base, "escaped")); err == nil {
		t.Fatal("the directory left the root")
	}
}

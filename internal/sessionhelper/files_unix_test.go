//go:build unix

package sessionhelper

import (
	"errors"
	"io/fs"
	"path/filepath"
	"syscall"
	"testing"
)

// A FIFO is refused without blocking the server.
func TestFilesRefusesAFIFO(t *testing.T) {
	h := newFilesHarness(t)
	if err := syscall.Mkfifo(filepath.Join(h.dir, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.Open("/fifo"); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("open /fifo: %v, want permission denied", err)
	}
	// Listing it as a directory is refused too, and does not block.
	if _, err := h.client.ReadDir("/fifo"); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("list /fifo: %v, want permission denied", err)
	}
}

// statvfs@openssh.com answers for the root's file system.
func TestFilesStatVFS(t *testing.T) {
	h := newFilesHarness(t)
	st, err := h.client.StatVFS("/")
	if err != nil || st.Bsize == 0 || st.Blocks == 0 {
		t.Fatalf("statvfs = %+v, %v", st, err)
	}
}

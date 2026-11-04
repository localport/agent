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
}

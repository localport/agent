package sessionhelper

import (
	"os"
	"path/filepath"
	"testing"

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

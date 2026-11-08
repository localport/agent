//go:build windows

package sessionhelper

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A junction, the mount-point reparse tag a volume mount point also carries,
// gives the client no way out of files_root.
func TestFilesRefusesAJunctionOutOfTheRoot(t *testing.T) {
	h := newFilesHarness(t)
	outside := filepath.Join(filepath.Dir(h.dir), "outside")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(h.dir, "j"), outside).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v: %s", err, out)
	}
	if f, err := h.client.Open("/j/secret"); err == nil {
		_ = f.Close()
		t.Fatal("a file reached through a junction out of the root")
	}
	if entries, err := h.client.ReadDir("/j"); err == nil {
		t.Fatalf("a directory listed through a junction out of the root: %v", entries)
	}
}

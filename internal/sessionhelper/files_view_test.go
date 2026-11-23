//go:build unix

package sessionhelper

import (
	"os"
	"path/filepath"
	"testing"
)

// filesView reports confined for a files_root or a privacy-confined home,
// home relative to the served folder with symlinks resolved, left out when
// it cannot be resolved or lies outside the folder, and whole disk for a
// folder that resolves to "/".
func TestFilesView(t *testing.T) {
	// t.TempDir is under /var on macOS, a symlink to /private/var.
	base := t.TempDir()
	home := filepath.Join(base, "Users", "x")
	for _, d := range []string{home, filepath.Join(base, "data"), filepath.Join(base, "Users", "xy")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(filepath.Join(base, "Users"), link); err != nil {
		t.Fatal(err)
	}
	real, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		root     string
		home     string
		privacy  bool
		confined bool
		rel      string
		whole    bool
	}{
		{"root is the disk", "/", home, false, true, real[1:], true},
		{"unconfined", "", home, false, false, "", false},
		{"privacy without root", "", home, true, true, ".", false},
		{"root is home", home, home, false, true, ".", false},
		{"root contains home", base, home, true, true, "Users/x", false},
		{"root through a symlink", link, home, false, true, "x", false},
		{"home through a symlink", filepath.Join(base, "Users"), filepath.Join(link, "x"), false, true, "x", false},
		{"root outside home", filepath.Join(base, "data"), home, false, true, "", false},
		{"sibling sharing a prefix", filepath.Join(base, "Users", "xy"), home, false, true, "", false},
		{"home missing", base, filepath.Join(base, "gone"), false, true, "", false},
		{"root missing", filepath.Join(base, "gone"), home, false, true, "", false},
	} {
		v := filesView(tc.root, tc.home, tc.privacy)
		if v.Confined != tc.confined || v.Home != tc.rel || v.WholeDisk != tc.whole {
			t.Errorf("%s: %+v, want confined %v home %q whole disk %v", tc.name, v, tc.confined, tc.rel, tc.whole)
		}
	}
}

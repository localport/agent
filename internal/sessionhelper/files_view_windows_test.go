package sessionhelper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// On Windows filesView matches root and home case-insensitively, drive
// letter included, accepts either separator, reports home slash separated,
// and never reports a drive root as the whole disk.
func TestFilesViewWindows(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "Users", "x")
	for _, d := range []string{home, filepath.Join(base, "data"), filepath.Join(base, "Users", "xy")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	real, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	vol := filepath.VolumeName(real)
	fromDrive := filepath.ToSlash(strings.TrimPrefix(real[len(vol):], `\`))
	for _, tc := range []struct {
		name string
		root string
		home string
		rel  string
	}{
		{"root is home, other case", strings.ToUpper(home), strings.ToLower(home), "."},
		{"root contains home, other case", strings.ToLower(base), home, "Users/x"},
		{"drive letter case", strings.ToLower(vol) + base[len(vol):], strings.ToUpper(vol) + home[len(vol):], "Users/x"},
		{"forward slashes", filepath.ToSlash(base), filepath.ToSlash(home), "Users/x"},
		{"drive root", vol + `\`, home, fromDrive},
		{"root outside home", filepath.Join(base, "data"), home, ""},
		{"sibling sharing a prefix", filepath.Join(base, "Users", "xy"), home, ""},
		{"home missing", base, filepath.Join(base, "gone"), ""},
	} {
		v := filesView(tc.root, tc.home, false)
		if !v.Confined || v.Home != tc.rel || v.WholeDisk {
			t.Errorf("%s: %+v, want confined home %q not whole disk", tc.name, v, tc.rel)
		}
	}
}

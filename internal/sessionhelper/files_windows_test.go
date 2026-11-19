//go:build windows

package sessionhelper

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Without files_root, "/" lists the drives read-only, "." is the home in /c:/
// form, and a file is reached by its /c:/ path or a relative name.
func TestFilesWithoutRootServesTheDrives(t *testing.T) {
	h := newHomeFilesHarness(t)
	entries, err := h.client.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	system := strings.ToLower(os.Getenv("SystemDrive"))
	if !slices.Contains(names, system) {
		t.Fatalf("list / = %v, want %s among them", names, system)
	}
	if fi, err := h.client.Stat("/"); err != nil || !fi.IsDir() {
		t.Fatalf("stat / = %v, %v", fi, err)
	}
	if err := h.client.Mkdir("/x"); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("mkdir /x = %v, want permission denied", err)
	}
	if _, err := h.client.Create("/x"); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("create /x = %v, want permission denied", err)
	}
	canonical, err := filepath.EvalSymlinks(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	start, err := winClientPath(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := h.client.RealPath("."); err != nil || got != start {
		t.Fatalf("realpath . = %q, %v, want %q", got, err, start)
	}
	if err := os.WriteFile(filepath.Join(h.dir, "a.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{start + "/a.txt", strings.ToUpper(start[:3]) + start[3:] + "/a.txt", "a.txt"} {
		f, err := h.client.Open(name)
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		b, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil || string(b) != "hi" {
			t.Fatalf("read %s = %q, %v", name, b, err)
		}
	}
	// statvfs answers for a directory and a file on the same volume alike,
	// and refuses a missing path.
	dirSt, err := h.client.StatVFS(start)
	if err != nil || dirSt.Blocks == 0 || dirSt.Bsize == 0 {
		t.Fatalf("statvfs %s = %+v, %v", start, dirSt, err)
	}
	if st, err := h.client.StatVFS(start + "/a.txt"); err != nil || st.Blocks != dirSt.Blocks || st.Bsize != dirSt.Bsize {
		t.Fatalf("statvfs of a file = %+v, %v, want the directory's volume %+v", st, err, dirSt)
	}
	if _, err := h.client.StatVFS(start + "/missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("statvfs of a missing path = %v, want no such file", err)
	}
	if _, err := h.client.StatVFS("/"); err == nil {
		t.Fatal("statvfs of the drive list answered")
	}
}

// A rename or link to another drive is refused with failure by the OS, as
// rename(2) refuses EXDEV, and moves nothing.
func TestFilesWithoutRootRefusesCrossDriveMoves(t *testing.T) {
	h := newHomeFilesHarness(t)
	canonical, err := filepath.EvalSymlinks(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	start, err := winClientPath(canonical)
	if err != nil {
		t.Fatal(err)
	}
	drives, err := osVirtualEntries()
	if err != nil {
		t.Fatal(err)
	}
	other := ""
	for _, d := range drives {
		if !strings.EqualFold("/"+d.Name(), start[:3]) {
			other = "/" + d.Name()
			break
		}
	}
	if other == "" {
		t.Skip("one drive only")
	}
	if err := os.WriteFile(filepath.Join(h.dir, "a"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := h.client.PosixRename("a", other+"/localport-cross-drive-test"); err == nil {
		t.Fatal("posix-rename across drives succeeded")
	}
	if err := h.client.Link("a", other+"/localport-cross-drive-test"); err == nil {
		t.Fatal("link across drives succeeded")
	}
	if _, err := os.Stat(filepath.Join(h.dir, "a")); err != nil {
		t.Fatalf("a refused move moved the file: %v", err)
	}
	// The OS refuses (ERROR_NOT_SAME_DEVICE): nothing copies across volumes.
	var results []string
	for _, ev := range h.events.list(t) {
		results = append(results, ev.Op+":"+ev.Result)
	}
	if want := []string{"rename:failure", "link:failure"}; !slices.Equal(results, want) {
		t.Fatalf("events %v, want %v", results, want)
	}
}

// A symlink's absolute target is stored as a drive path, read back as /c:/.
func TestFilesWithoutRootMapsSymlinkTargets(t *testing.T) {
	h := newHomeFilesHarness(t)
	canonical, err := filepath.EvalSymlinks(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	start, err := winClientPath(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.dir, "target"), []byte("t"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := h.client.Symlink(start+"/target", "link"); err != nil {
		t.Skipf("symlinks need SeCreateSymbolicLinkPrivilege or developer mode: %v", err)
	}
	if got, err := os.Readlink(filepath.Join(h.dir, "link")); err != nil || !strings.EqualFold(got, filepath.Join(canonical, "target")) {
		t.Fatalf("stored target = %q, %v", got, err)
	}
	if got, err := h.client.ReadLink("link"); err != nil || !strings.EqualFold(got, start+"/target") {
		t.Fatalf("readlink = %q, %v, want %q", got, err, start+"/target")
	}
}

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

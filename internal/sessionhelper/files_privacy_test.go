//go:build unix

package sessionhelper

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// privacyHome builds a home with the gated folders, a Photos library, an
// open folder and symlinks into a gated folder.
func privacyHome(t *testing.T) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	for _, d := range []string{"Desktop", "Documents", "Downloads", "Library/Mail", "Pictures/Photos Library.photoslibrary", "Pictures/Old.PhotosLibrary", "Code"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"Desktop/secret", "Library/Mail/inbox", "Pictures/Photos Library.photoslibrary/db", "Code/notes"} {
		if err := os.WriteFile(filepath.Join(home, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"desk": "Desktop", "Code/up": "../Desktop", "Code/loop": "loop"} {
		if err := os.Symlink(target, filepath.Join(home, link)); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

// The walk never looks inside a gated folder, however it is named: each
// lstat and readlink it makes is in an open folder.
func TestPrivacyWalkNeverLooksInside(t *testing.T) {
	home := privacyHome(t)
	root, err := os.OpenRoot(home)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	g := newPrivacyGuard(home)
	gated := []string{"Desktop/", "Library/", "Pictures/Photos Library.photoslibrary/"}
	var looked []string
	lstat := func(n string) (fs.FileInfo, error) { looked = append(looked, n); return root.Lstat(n) }
	readlink := func(n string) (string, error) { looked = append(looked, n); return root.Readlink(n) }
	for _, tc := range []struct {
		name    string
		refused bool
	}{
		{"Desktop/secret", true},
		{"desk/secret", true},
		{"Code/up/secret", true},
		{"Code/../Desktop/secret", true},
		{"Library/Mail/inbox", true},
		{"Pictures/Photos Library.photoslibrary/db", true},
		{"Code/notes", false},
		{"Code/loop", false},
		{"missing/file", false},
	} {
		looked = looked[:0]
		err := g.walk(lstat, readlink, ".", rel(tc.name), true, true)
		if got := errors.Is(err, fs.ErrPermission); got != tc.refused {
			t.Errorf("%s: %v, refused %v", tc.name, err, tc.refused)
		}
		for _, n := range looked {
			for _, p := range gated {
				if strings.HasPrefix(n, p) {
					t.Errorf("%s: looked up %s inside a gated folder", tc.name, n)
				}
			}
		}
	}
}

// A gated folder's own metadata is a lookup in its parent: listed and
// stat'ed, never opened.
func TestPrivacyWalkUseOfTheFolderItself(t *testing.T) {
	home := privacyHome(t)
	root, err := os.OpenRoot(home)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	g := newPrivacyGuard(home)
	if err := g.walk(root.Lstat, root.Readlink, ".", "Desktop", true, false); err != nil {
		t.Errorf("stat Desktop: %v", err)
	}
	if err := g.walk(root.Lstat, root.Readlink, ".", "Desktop", true, true); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("open Desktop: %v, want permission denied", err)
	}
}

// Without Full Disk Access a session serves the home: open folders work, a
// gated folder is listed but refuses to open, and nothing reaches it through
// a symlink, a rename, a new folder or a delete.
func TestFilesWithoutFullDiskAccess(t *testing.T) {
	home := privacyHome(t)
	h := servePrivacyHarness(t, home, home, home, true, FilesAccess{Download: true, Upload: true})
	entries, err := h.client.ReadDir("/")
	if err != nil {
		t.Fatalf("list home: %v", err)
	}
	if !slicesContainName(entries, "Desktop") {
		t.Error("home listing has no Desktop")
	}
	if _, err := h.client.Lstat("/Desktop"); err != nil {
		t.Errorf("lstat Desktop: %v", err)
	}
	if fi, err := h.client.Stat("/desk"); err != nil || !fi.IsDir() {
		t.Errorf("stat Desktop through a symlink: %v", err)
	}
	if f, err := h.client.Open("/Code/notes"); err != nil {
		t.Errorf("open Code/notes: %v", err)
	} else {
		_ = f.Close()
	}
	refused := map[string]func() error{
		"list Desktop":     func() error { _, err := h.client.ReadDir("/Desktop"); return err },
		"open via symlink": func() error { _, err := h.client.Open("/desk/secret"); return err },
		"open Library":     func() error { _, err := h.client.Open("/Library/Mail/inbox"); return err },
		"mkdir in Desktop": func() error { return h.client.Mkdir("/Desktop/new") },
		"move into":        func() error { return h.client.Rename("/Code/notes", "/Desktop/notes") },
		"move out":         func() error { return h.client.Rename("/Desktop/secret", "/Code/secret") },
		"move Desktop":     func() error { return h.client.Rename("/Desktop", "/Code/Desk") },
		"posix move out":   func() error { return h.client.PosixRename("/Desktop/secret", "/Code/secret") },
		"link out":         func() error { return h.client.Link("/Desktop/secret", "/Code/secret") },
		"chmod Desktop":    func() error { return h.client.Chmod("/Desktop", 0o700) },
		"list mixed case":  func() error { _, err := h.client.ReadDir("/Pictures/Old.PhotosLibrary"); return err },
		"remove Desktop":   func() error { return h.client.Remove("/Desktop") },
	}
	for name, op := range refused {
		if err := op(); !errors.Is(err, fs.ErrPermission) {
			t.Errorf("%s: %v, want permission denied", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(home, "Code/notes")); err != nil {
		t.Errorf("refused move changed the source: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(home, "Code/secret")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("refused move or link out created Code/secret: %v", err)
	}
}

// A files_root inside a gated folder is refused.
func TestFilesRootInsideAGatedFolderIsRefused(t *testing.T) {
	home := privacyHome(t)
	if err := ServeFiles(nil, filepath.Join(home, "Desktop"), home, true, FilesAccess{}, nil); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("ServeFiles = %v, want permission denied", err)
	}
}

func slicesContainName(entries []fs.FileInfo, name string) bool {
	for _, e := range entries {
		if e.Name() == name {
			return true
		}
	}
	return false
}

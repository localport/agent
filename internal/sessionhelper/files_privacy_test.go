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
	g, base := homeGuard(t, home)
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
		_, err := g.walk(lstat, readlink, ".", base, rel(tc.name), true, true)
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
	g, base := homeGuard(t, home)
	if _, err := g.walk(root.Lstat, root.Readlink, ".", base, "Desktop", true, false); err != nil {
		t.Errorf("stat Desktop: %v", err)
	}
	if _, err := g.walk(root.Lstat, root.Readlink, ".", base, "Desktop", true, true); !errors.Is(err, fs.ErrPermission) {
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

// homeGuard returns a guard for home on a system with no Users directory, and
// home's directories from checkRoot.
func homeGuard(t *testing.T, home string) (privacyGuard, []fs.FileInfo) {
	t.Helper()
	g, err := newPrivacyGuard(t.TempDir(), home)
	if err != nil {
		t.Fatal(err)
	}
	base, err := g.checkRoot(home)
	if err != nil {
		t.Fatal(err)
	}
	return g, base
}

// usersTop builds a system top with Users/other/{Desktop/secret,Code}, an
// alias symlink to Users and Volumes/ext; the login's home is elsewhere.
func usersTop(t *testing.T) (top, home string) {
	t.Helper()
	top = t.TempDir()
	for _, d := range []string{"Users/other/Desktop", "Users/other/Code", "Volumes/ext/u/Desktop"} {
		if err := os.MkdirAll(filepath.Join(top, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(top, "Users/other/Desktop/secret"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("Users", filepath.Join(top, "alias")); err != nil {
		t.Fatal(err)
	}
	return top, privacyHome(t)
}

// Another account's folders under Users are refused through any path,
// without a lookup inside them.
func TestPrivacyGuardRecognizesUsersHomes(t *testing.T) {
	top, home := usersTop(t)
	g, err := newPrivacyGuard(top, home)
	if err != nil {
		t.Fatal(err)
	}
	desktop := filepath.ToSlash(filepath.Join(top, "Users/other/Desktop")) + "/"
	var looked []string
	lstat := func(n string) (fs.FileInfo, error) { looked = append(looked, n); return os.Lstat(n) }
	readlink := func(n string) (string, error) { looked = append(looked, n); return os.Readlink(n) }
	for _, tc := range []struct {
		name    string
		refused bool
	}{
		{"Users/other/Desktop/secret", true},
		{"alias/other/Desktop/secret", true},
		{"Users/other/Code/../Desktop/secret", true},
		{"Users/other/Code", false},
	} {
		looked = looked[:0]
		_, err := g.walk(lstat, readlink, "/", rootBase, filepath.ToSlash(filepath.Join(top, tc.name)), true, true)
		if got := errors.Is(err, fs.ErrPermission); got != tc.refused {
			t.Errorf("%s: %v, refused %v", tc.name, err, tc.refused)
		}
		for _, n := range looked {
			if strings.HasPrefix(n, desktop) {
				t.Errorf("%s: looked up %s inside a gated folder", tc.name, n)
			}
		}
	}

	// A files root of Users serves other homes through privacyFS.
	users := filepath.Join(top, "Users")
	base, err := g.checkRoot(users)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(users)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	p := privacyFS{rootFS: rootFS{root: root}, guard: g, base: base}
	if _, err := p.Stat("/other/Desktop/secret"); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("stat other/Desktop/secret: %v, want permission denied", err)
	}
	if _, err := p.Stat("/other/Code"); err != nil {
		t.Errorf("stat other/Code: %v", err)
	}
}

// A root that reaches Volumes through "link/.." is refused.
func TestCheckRootResolvesDotDotAfterALink(t *testing.T) {
	top, home := usersTop(t)
	g, err := newPrivacyGuard(top, home)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(top, "Volumes/ext/u"), filepath.Join(top, "Users/other/Code/link")); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(top, "Users/other/Code/link") + "/.."
	if _, err := g.checkRoot(root); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("checkRoot(%s) = %v, want permission denied", root, err)
	}
}

// A relative home is refused.
func TestPrivacyGuardRefusesARelativeHome(t *testing.T) {
	for _, home := range []string{"", "home"} {
		if _, err := newPrivacyGuard(t.TempDir(), home); !errors.Is(err, errHomeNotAbsolute) {
			t.Errorf("home %q: %v, want errHomeNotAbsolute", home, err)
		}
		if err := ServeFiles(nil, t.TempDir(), home, true, FilesAccess{}, nil); !errors.Is(err, errHomeNotAbsolute) {
			t.Errorf("ServeFiles home %q: %v, want errHomeNotAbsolute", home, err)
		}
	}
}

// A login home inside a protected directory is refused and none of its
// folders is read.
func TestPrivacyGuardHomeInsideProtected(t *testing.T) {
	top, _ := usersTop(t)
	g, err := newPrivacyGuard(top, filepath.Join(top, "Volumes/ext/u"))
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("newPrivacyGuard = %v, want permission denied", err)
	}
	if len(g.dirs) != 1 {
		t.Errorf("guard holds %d directories, want Volumes only", len(g.dirs))
	}
}

//go:build cgo && (linux || darwin)

package sessionhelper

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"github.com/localport/agent/internal/launcher"
)

// Any Full Disk Access reading but granted turns the guard on and confines
// the session to files_root, else home; no reading or granted leaves it off.
func TestFilesServerArgsFollowFullDiskAccess(t *testing.T) {
	home := t.TempDir()
	access := FilesAccess{Download: true}
	cases := []struct {
		fda, root          string
		wantRoot, wantHome string
		wantPrivacy        bool
	}{
		{"", "", "", home, false},
		{launcher.FullDiskAccessGranted, "", "", home, false},
		{launcher.FullDiskAccessGranted, "/srv/data", "/srv/data", "", false},
		{launcher.FullDiskAccessDenied, "", home, home, true},
		{launcher.FullDiskAccessUnknown, "", home, home, true},
		{launcher.FullDiskAccessDenied, "/srv/data", "/srv/data", home, true},
	}
	for _, c := range cases {
		args, err := filesServerArgs(access, c.root, home, c.fda)
		if err != nil {
			t.Fatalf("fda %q root %q: %v", c.fda, c.root, err)
		}
		want := []string{"localport-session", FilesServerMode, access.Arg(), c.wantRoot, c.wantHome, privacyArg(c.wantPrivacy)}
		if !slices.Equal(args, want) {
			t.Errorf("fda %q root %q: args %q, want %q", c.fda, c.root, args, want)
		}
		if on, ok := ParsePrivacyArg(args[5]); !ok || on != c.wantPrivacy {
			t.Errorf("fda %q: ParsePrivacyArg(%q) = %v, %v; want %v", c.fda, args[5], on, ok, c.wantPrivacy)
		}
	}
	if _, ok := ParsePrivacyArg("yes"); ok {
		t.Error("ParsePrivacyArg accepted an unknown value")
	}
}

// A home inside a protected directory is left out of the view; without a
// root the session is refused.
func TestFilesSessionHomeInsideProtected(t *testing.T) {
	top, _ := usersTop(t)
	privacyTop = top
	t.Cleanup(func() { privacyTop = "/" })
	home := filepath.Join(top, "Volumes/ext/u")
	_, v, err := filesSession(FilesAccess{}, top, home, launcher.FullDiskAccessDenied)
	if err != nil || v.Home != "" {
		t.Errorf("root %s: view %+v, err %v; want no home", top, v, err)
	}
	if _, _, err := filesSession(FilesAccess{}, "", home, launcher.FullDiskAccessDenied); !errors.Is(err, errProtectedRoot) {
		t.Errorf("no root: %v, want errProtectedRoot", err)
	}
	if _, _, err := filesSession(FilesAccess{}, top, "home", launcher.FullDiskAccessDenied); !errors.Is(err, errHomeNotAbsolute) {
		t.Errorf("relative home: %v, want errHomeNotAbsolute", err)
	}
}

// Without Full Disk Access a root inside a protected folder is refused before
// filesView reads it; with the grant the same root is served.
func TestFilesSessionRefusesAProtectedRoot(t *testing.T) {
	home := privacyHome(t)
	protected := filepath.Join(home, "Desktop", "proj")
	if _, _, err := filesSession(FilesAccess{}, protected, home, launcher.FullDiskAccessDenied); !errors.Is(err, errProtectedRoot) {
		t.Fatalf("denied, root in Desktop: err %v, want errProtectedRoot", err)
	}
	if _, v, err := filesSession(FilesAccess{}, filepath.Join(home, "Code"), home, launcher.FullDiskAccessDenied); err != nil || !v.Confined {
		t.Fatalf("denied, root Code: view %+v, err %v; want confined", v, err)
	}
	if _, _, err := filesSession(FilesAccess{}, protected, home, launcher.FullDiskAccessGranted); err != nil {
		t.Fatalf("granted, root in Desktop: %v", err)
	}
}

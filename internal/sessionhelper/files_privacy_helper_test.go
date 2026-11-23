//go:build cgo && (linux || darwin)

package sessionhelper

import (
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

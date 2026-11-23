//go:build cgo && darwin

package sessionhelper

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/localport/agent/internal/launcher"
)

// The system guard refuses a /Users home's Desktop for a login whose home is
// elsewhere, through /Users and through its firmlink path.
func TestFilesSessionRefusesUsersHomeFolders(t *testing.T) {
	me, err := os.UserHomeDir()
	if err != nil || !strings.HasPrefix(me, "/Users/") {
		t.Skipf("home %q is not under /Users", me)
	}
	home := t.TempDir()
	for _, root := range []string{
		filepath.Join(me, "Desktop", "x"),
		filepath.Join("/System/Volumes/Data", me, "Desktop", "x"),
	} {
		if _, _, err := filesSession(FilesAccess{}, root, home, launcher.FullDiskAccessDenied); !errors.Is(err, errProtectedRoot) {
			t.Errorf("root %s: %v, want errProtectedRoot", root, err)
		}
	}
}

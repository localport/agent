package sessionhelper

import (
	"path/filepath"
	"strings"

	"github.com/localport/agent/internal/launcher"
)

// filesView returns the view sent to the client. Home is the login's home
// relative to the served folder ("." when equal), omitted when unresolvable,
// outside the folder or longer than launcher.MaxFilesHome. Paths compare with
// symlinks resolved. WholeDisk is a confined folder resolving to "/".
func filesView(root, home string, privacy bool) (v launcher.Started) {
	if root == "" && privacy {
		root = home
	}
	if root == "" {
		return v
	}
	v.Confined = true
	r, err := filepath.EvalSymlinks(root)
	if err != nil {
		return v
	}
	v.WholeDisk = r == "/"
	h, err := filepath.EvalSymlinks(home)
	if err != nil {
		return v
	}
	rel, err := filepath.Rel(r, h)
	if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return v
	}
	if rel = filepath.ToSlash(rel); launcher.ValidFilesHome(rel) {
		v.Home = rel
	}
	return v
}

//go:build cgo && (linux || darwin)

package sessionhelper

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/localport/agent/internal/launcher"
)

// filesPrivacy reports whether a files session runs with the privacy guard:
// a launcher reading of Full Disk Access (macOS only) that is not granted.
func filesPrivacy(fullDiskAccess string) bool {
	return fullDiskAccess != "" && fullDiskAccess != launcher.FullDiskAccessGranted
}

// errProtectedRoot refuses a files session without Full Disk Access whose
// root is inside or equal to a folder macOS gates.
var errProtectedRoot = errors.New("files root is in a folder macOS protects")

// filesSession returns the file server's command line and the client's view.
// With the privacy guard, a root (else home) inside or equal to a protected
// folder is refused with errProtectedRoot before any lookup; a home inside one
// is left out of the view.
func filesSession(access FilesAccess, root, home, fullDiskAccess string) ([]string, launcher.Started, error) {
	privacy := filesPrivacy(fullDiskAccess)
	viewHome := home
	if privacy {
		guard, err := systemPrivacyGuard(home)
		if errors.Is(err, fs.ErrPermission) {
			viewHome = ""
		} else if err != nil {
			return nil, launcher.Started{}, err
		}
		checked := root
		if checked == "" {
			checked = home
		}
		if _, err := guard.checkRoot(checked); errors.Is(err, fs.ErrPermission) {
			return nil, launcher.Started{}, fmt.Errorf("%w: %w", errProtectedRoot, err)
		} else if err != nil {
			return nil, launcher.Started{}, err
		}
	}
	args, err := filesServerArgs(access, root, home, fullDiskAccess)
	if err != nil {
		return nil, launcher.Started{}, err
	}
	return args, filesView(root, viewHome, privacy), nil
}

// filesServerArgs is the FilesServerMode command line. Without Full Disk
// Access the session is confined to root, else home, with the guard on;
// otherwise filesHome checks home.
func filesServerArgs(access FilesAccess, root, home, fullDiskAccess string) ([]string, error) {
	privacy := filesPrivacy(fullDiskAccess)
	if privacy {
		if root == "" {
			root = home
		}
	} else {
		var err error
		if home, err = filesHome(root, home); err != nil {
			return nil, err
		}
	}
	return []string{"localport-session", FilesServerMode, access.Arg(), root, home, privacyArg(privacy)}, nil
}

// privacyArg is the FilesServerMode privacy argument ParsePrivacyArg reads.
func privacyArg(on bool) string {
	if on {
		return filesPrivacyOn
	}
	return filesPrivacyOff
}

//go:build cgo && (linux || darwin)

package sessionhelper

import "github.com/localport/agent/internal/launcher"

// filesPrivacy reports whether a files session runs with the privacy guard:
// a launcher reading of Full Disk Access (macOS only) that is not granted.
func filesPrivacy(fullDiskAccess string) bool {
	return fullDiskAccess != "" && fullDiskAccess != launcher.FullDiskAccessGranted
}

// filesServerArgs is the FilesServerMode command line for a files session of
// the login whose home is home. Without Full Disk Access (macOS) the session
// is confined to root (files_root), else home, with the privacy guard on and
// home naming the folders it gates; otherwise root may be empty and home is
// checked by filesHome.
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

//go:build cgo && (linux || darwin)

package sessionhelper

// PAMAvailable reports whether this build opens PAM sessions.
func PAMAvailable() bool { return pamAvailable }

// LookupIDs resolves an account's uid and primary gid through NSS.
func LookupIDs(name string) (uid, gid uint32, err error) {
	a, err := lookupAccount(name)
	if err != nil {
		return 0, 0, err
	}
	return a.UID, a.GID, nil
}

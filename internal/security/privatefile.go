package security

import (
	"io"
	"os"
)

// Owner-only reads of private key material.
//
// Two properties the plain os package does not provide:
//
//   - Validation runs on an open descriptor, never on a path. Checking a path
//     and then opening it leaves a window in which the file can be replaced.
//   - Symlinks are refused rather than followed, so a link planted in advance
//     cannot redirect a key to a location its owner can read.
//
// On Unix the mode bits carry the policy. On Windows the Go runtime synthesises
// them from the read-only attribute alone, so they say nothing about who can
// read the file; the DACL carries the policy there instead.

// ReadPrivateFile reads a file that must be reachable only by its owner.
func ReadPrivateFile(path string) ([]byte, error) {
	f, err := OpenPrivateFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// OpenPrivateFile opens a file for reading and refuses it if anything other
// than its owner can reach it. The caller closes the returned handle.
func OpenPrivateFile(path string) (*os.File, error) {
	f, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	if err := verifyPrivate(f, path); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

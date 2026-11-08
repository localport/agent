//go:build !linux

package sessionhelper

import "os"

// renameNoReplace is the check-then-rename path on systems without
// RENAME_NOREPLACE.
func renameNoReplace(root *os.Root, from, to string) error {
	return checkThenRename(root, from, to)
}

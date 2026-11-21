//go:build !linux && !darwin

package sessionhelper

import "os"

// renameNoReplace is the check-then-rename path where no atomic flag exists.
func renameNoReplace(root *os.Root, from, to string) error {
	return checkThenRename(root, from, to)
}

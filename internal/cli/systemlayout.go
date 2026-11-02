package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// moveSpool moves the recording spool an earlier layout kept in the device
// directory into the identity directory, unless one is already there.
func moveSpool(from, to string) error {
	fi, err := os.Lstat(from)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %s: %w", from, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory; move it aside, then run the command again", from)
	}
	if _, err := os.Lstat(to); err == nil {
		fmt.Fprintf(os.Stderr, "  kept %s; %s already exists\n", from, to)
		return nil
	}
	if err := os.Rename(from, to); err != nil {
		return fmt.Errorf("move %s to %s: %w", from, to, err)
	}
	return nil
}

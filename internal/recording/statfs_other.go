//go:build !linux && !darwin && !windows

package recording

import (
	"errors"
	"fmt"
)

// availableBytes has no implementation where terminal sessions, and so
// recordings, do not run; a segment write there fails with this error.
func availableBytes(path string) (uint64, error) {
	return 0, fmt.Errorf("free space of %s: %w", path, errors.ErrUnsupported)
}

// diskFull is false where recordings do not run.
func diskFull(error) bool { return false }

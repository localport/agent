//go:build cgo && darwin

package sessionhelper

import "errors"

// closeRangeCloexec has no macOS equivalent; closeExtraFDs walks /dev/fd.
func closeRangeCloexec(uint) error { return errors.ErrUnsupported }

//go:build !darwin && !linux

package service

import (
	"errors"
	"os"
)

// openBundleFile is unsupported: launchd runs only on macOS.
func openBundleFile(string) (*os.File, error) { return nil, errors.ErrUnsupported }

package security

import (
	"errors"
	"os"
)

// Windows has no system files: the device directory is guarded by its DACL
// through the private file functions.

const (
	SystemRunLockPerm    os.FileMode = 0o660
	SystemConfigLockPerm os.FileMode = 0o600
)

func CheckSystemDir(string) error                     { return errors.ErrUnsupported }
func EnsureSystemDir(string, int) error               { return errors.ErrUnsupported }
func ReadSystemFile(string) ([]byte, error)           { return nil, errors.ErrUnsupported }
func WriteSystemFileAtomic(string, []byte, int) error { return errors.ErrUnsupported }
func OpenSystemRunLock(string) (*os.File, error)      { return nil, errors.ErrUnsupported }
func OpenSystemLock(string, int, os.FileMode) (*os.File, error) {
	return nil, errors.ErrUnsupported
}

package identity

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isSharingViolation reports a Windows open or delete refused because another
// handle (an antivirus or backup scan) holds the file without delete sharing.
func isSharingViolation(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}

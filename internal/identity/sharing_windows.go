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

// purgeRemovesStoreLock is false on Windows: a deleted file stays delete
// pending while any handle is open, and an open of it meanwhile fails with
// ERROR_ACCESS_DENIED rather than finding the lock busy. The store lock stays;
// nothing removes Root on Windows (removeAgentDirs).
const purgeRemovesStoreLock = false

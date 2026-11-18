//go:build !windows

package identity

// isSharingViolation is false off Windows, where an open handle never blocks a
// delete.
func isSharingViolation(error) bool { return false }

// purgeRemovesStoreLock: an unlinked file stays usable by the handles open on
// it, and a holder that opened it before finds it unlinked (lockStillLinked),
// so PurgeDevices may delete the store lock and let Root be removed.
const purgeRemovesStoreLock = true

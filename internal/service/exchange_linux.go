package service

import "golang.org/x/sys/unix"

// exchange atomically swaps the directory entries a and b, both existing
// (renameat2 RENAME_EXCHANGE). launchd runs only on macOS; Linux builds it
// so the launchd tests run there.
func exchange(a, b string) error {
	return unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE)
}

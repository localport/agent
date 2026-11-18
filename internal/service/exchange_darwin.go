package service

import "golang.org/x/sys/unix"

// exchange atomically swaps the directory entries a and b, both existing
// (renamex_np RENAME_SWAP).
func exchange(a, b string) error { return unix.RenamexNp(a, b, unix.RENAME_SWAP) }

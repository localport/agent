//go:build netbsd

package security

import "syscall"

// refusedLinkErrno is the errno open(2) returns for a symlink with O_NOFOLLOW.
const refusedLinkErrno = syscall.EFTYPE

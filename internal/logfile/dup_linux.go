package logfile

import "golang.org/x/sys/unix"

// dupOnto makes newfd a copy of oldfd (dup3: arm64 has no dup2).
func dupOnto(oldfd, newfd int) error { return unix.Dup3(oldfd, newfd, 0) }

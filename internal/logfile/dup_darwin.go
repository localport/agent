package logfile

import "golang.org/x/sys/unix"

// dupOnto makes newfd a copy of oldfd.
func dupOnto(oldfd, newfd int) error { return unix.Dup2(oldfd, newfd) }

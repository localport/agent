//go:build cgo && darwin

// Package testsys makes the macOS calls the session helper's tests need and
// Go's standard library lacks: blocking a signal on the calling thread, and
// reading the process's audit session. Only tests import it.
package testsys

/*
#include <pthread.h>
#include <signal.h>

static int lp_block(int sig) {
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, sig);
	return pthread_sigmask(SIG_BLOCK, &set, NULL);
}
*/
import "C"

import "syscall"

// Block adds sig to the calling thread's signal mask. The caller locks the
// goroutine to its thread first.
func Block(sig syscall.Signal) error {
	if rc := C.lp_block(C.int(sig)); rc != 0 {
		return syscall.Errno(rc)
	}
	return nil
}

//go:build !windows

package cli

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/launcher"
)

// reloadSignals delivers SIGHUP, which the service managers send on reload.
func reloadSignals() (<-chan os.Signal, func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	return sig, func() { signal.Stop(sig) }
}

// The descriptors root passes a foreground run it relays as the agent
// account (runHeldAsAgent): the listening control socket and a duplicate of
// the run lock descriptor root holds (the device config directory,
// config.LockRunFile), the first two ExtraFiles. Variables so tests can
// pass descriptors of their own.
var (
	controlSocketFD uintptr = 3
	runLockFD       uintptr = 4
)

// inheritedDescriptor is descriptor fd as root passed it, marked
// close-on-exec first, so no process this one starts inherits it.
func inheritedDescriptor(fd uintptr, name string) *os.File {
	syscall.CloseOnExec(int(fd))
	return os.NewFile(fd, name)
}

// inheritedControl serves the control socket root passed, after
// launcher.ControlListenerOn checks it is that socket.
func inheritedControl() (*launcher.ControlListener, error) {
	return launcher.ControlListenerOn(inheritedDescriptor(controlSocketFD, "control socket"))
}

// inheritedRunLock adopts the run lock of file root holds and passed, the
// locked device config directory (config.AdoptRunLock). release only closes this copy: root releases the
// lock once it has removed the control socket.
func inheritedRunLock(file config.LocalConfigFile) (release func() error, err error) {
	lock := inheritedDescriptor(runLockFD, "run.lock")
	if err := config.AdoptRunLock(file, lock); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return lock.Close, nil
}

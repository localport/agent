package cli

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"
)

// holdServiceConfig takes the service configuration lock on its own OS
// thread, which a mutex requires, and releases it when release is closed.
func holdServiceConfig(t *testing.T) (release chan struct{}, done chan struct{}) {
	t.Helper()
	release, done, held := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		defer close(done)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		unlock, err := lockServiceConfig(context.Background())
		held <- err
		if err != nil {
			return
		}
		<-release
		unlock()
	}()
	if err := <-held; err != nil {
		t.Fatalf("take the service configuration lock: %v", err)
	}
	return release, done
}

func requireElevated(t *testing.T) {
	t.Helper()
	if !privileged() {
		t.Skip("the service configuration namespace needs an elevated Administrator")
	}
}

func shortServiceConfigWait(t *testing.T) {
	t.Helper()
	old := serviceConfigLockWait
	serviceConfigLockWait = time.Second
	t.Cleanup(func() { serviceConfigLockWait = old })
}

// Every writer of the service definitions refuses with AG091 while another
// process holds the lock, before it changes anything.
func TestServiceWritersRefuseWhileTheConfigLockIsHeld(t *testing.T) {
	requireElevated(t)
	shortServiceConfigWait(t)
	release, done := holdServiceConfig(t)
	defer func() { close(release); <-done }()

	writers := map[string]func() error{
		"service install":   func() error { return installService(currentInvoker(true)) },
		"service uninstall": func() error { return uninstallService(currentInvoker(true), false) },
		"connect":           func() error { return (&deviceService{}).install() },
	}
	for name, write := range writers {
		if err := write(); !errors.Is(err, errServiceConfigBusy) || !errors.Is(err, errServiceConfigHeld) {
			t.Errorf("%s = %v, want errServiceConfigBusy after waiting for the holder", name, err)
		}
	}
}

// The lock stays one mutex when its first holder, the namespace's creator,
// releases it and closes its namespace handle while a second holder that
// opened the namespace holds it: a third writer must still wait.
func TestServiceConfigLockSurvivesItsCreatorClosing(t *testing.T) {
	requireElevated(t)
	shortServiceConfigWait(t)
	firstRelease, firstDone := holdServiceConfig(t)

	waiting := make(chan struct{}, 1)
	serviceConfigWaiting = func() { waiting <- struct{}{} }
	t.Cleanup(func() { serviceConfigWaiting = nil })
	secondHeld, secondRelease, secondDone := make(chan error, 1), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(secondDone)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		unlock, err := lockServiceConfig(context.Background())
		secondHeld <- err
		if err != nil {
			return
		}
		<-secondRelease
		unlock()
	}()
	// The second writer has opened the namespace and is waiting on the
	// mutex when the creator lets go.
	<-waiting
	serviceConfigWaiting = nil
	close(firstRelease)
	<-firstDone
	if err := <-secondHeld; err != nil {
		t.Fatalf("second holder: %v", err)
	}
	defer func() {
		if secondRelease != nil {
			close(secondRelease)
			<-secondDone
		}
	}()

	// The third writer opens the namespace after its creator closed it and
	// must wait on the same mutex: it times out while the second holds it,
	// rather than failing to open or taking a different mutex.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	unlock, err := lockServiceConfig(context.Background())
	if err == nil {
		unlock()
		t.Fatal("a third writer took the lock while the second held it")
	}
	if !errors.Is(err, errServiceConfigHeld) {
		t.Fatalf("third writer = %v, want a wait that timed out (errServiceConfigHeld)", err)
	}
	close(secondRelease)
	<-secondDone
	secondRelease = nil
	unlock, err = lockServiceConfig(context.Background())
	if err != nil {
		t.Fatalf("third writer after the second released = %v", err)
	}
	unlock()
}

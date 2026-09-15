//go:build windows

package netmon

import (
	"context"
	"log/slog"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// winSource registers for iphlpapi NotifyIpInterfaceChange. The callback wakes
// the monitor on any IP interface change, and the monitor's address diff
// filters out irrelevant ones.
type winSource struct {
	logger *slog.Logger

	once sync.Once
	// registered is closed once watch finishes registering. Close waits on
	// it so a late registration cannot leak.
	registered chan struct{}

	mu        sync.Mutex
	handle    uintptr
	hasHandle bool
}

// NewLazySystemDLL searches only %SystemRoot%\System32. The default search
// order would load an iphlpapi.dll placed next to localport.exe.
var (
	modIphlpapi                 = windows.NewLazySystemDLL("iphlpapi.dll")
	procNotifyIPInterfaceChange = modIphlpapi.NewProc("NotifyIpInterfaceChange")
	procCancelMibChangeNotify2  = modIphlpapi.NewProc("CancelMibChangeNotify2")
)

const afUnspec = 0 // AF_UNSPEC, watch both IPv4 and IPv6.

func newSource(logger *slog.Logger) source {
	// Return nil if the DLL or procedure is missing. The monitor then polls.
	if err := procNotifyIPInterfaceChange.Find(); err != nil {
		logger.Debug("NotifyIpInterfaceChange unavailable; using address poll", slog.Any("error", err))
		return nil
	}
	if err := procCancelMibChangeNotify2.Find(); err != nil {
		logger.Debug("CancelMibChangeNotify2 unavailable; using address poll", slog.Any("error", err))
		return nil
	}
	return &winSource{logger: logger, registered: make(chan struct{})}
}

func (s *winSource) watch(ctx context.Context, wake chan<- struct{}) {
	// Called on an OS worker thread. The non-blocking send coalesces bursts.
	cb := syscall.NewCallback(func(_ uintptr, _ uintptr, _ uintptr) uintptr {
		select {
		case wake <- struct{}{}:
		default:
		}
		return 0
	})

	var handle uintptr
	// NotifyIpInterfaceChange(Family, Callback, CallerContext,
	// InitialNotification, *Handle) returns NO_ERROR (0) on success.
	r1, _, _ := procNotifyIPInterfaceChange.Call(
		uintptr(afUnspec),
		cb,
		0, // CallerContext, unused
		0, // InitialNotification FALSE
		uintptr(unsafe.Pointer(&handle)),
	)
	if r1 != 0 {
		// Registration failed. The monitor's fallback poll still runs.
		s.logger.Debug("NotifyIpInterfaceChange registration failed; relying on safety poll", slog.Uint64("code", uint64(r1)))
		close(s.registered)
		return
	}
	s.mu.Lock()
	s.handle = handle
	s.hasHandle = true
	s.mu.Unlock()
	close(s.registered)

	<-ctx.Done()
	s.cancel()
}

func (s *winSource) cancel() {
	s.once.Do(func() {
		s.mu.Lock()
		handle, ok := s.handle, s.hasHandle
		s.mu.Unlock()
		if ok {
			_, _, _ = procCancelMibChangeNotify2.Call(handle)
		}
	})
}

// Close cancels the OS notification. It waits for registration to finish so
// the handle exists.
func (s *winSource) Close() error {
	<-s.registered
	s.cancel()
	return nil
}

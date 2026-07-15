//go:build windows

package netmon

import (
	"context"
	"log/slog"
	"sync"
	"syscall"
	"unsafe"
)

// winSource uses iphlpapi's NotifyIpInterfaceChange: the OS invokes a callback
// on any IP-interface change (up/down, address add/remove, connectivity flip),
// so detection is event-driven with zero idle cost (the Windows equivalent of
// Linux netlink / BSD PF_ROUTE). The callback just wakes the monitor; the
// portable address diff decides whether the change is real.
type winSource struct {
	logger *slog.Logger

	once      sync.Once
	handle    uintptr
	hasHandle bool
}

var (
	modIphlpapi                 = syscall.NewLazyDLL("iphlpapi.dll")
	procNotifyIPInterfaceChange = modIphlpapi.NewProc("NotifyIpInterfaceChange")
	procCancelMibChangeNotify2  = modIphlpapi.NewProc("CancelMibChangeNotify2")
)

const afUnspec = 0 // AF_UNSPEC, watch both IPv4 and IPv6.

func newSource(logger *slog.Logger) source {
	// Missing DLL/proc (unusually stripped Windows) → nil so the monitor uses
	// its portable address poll instead.
	if err := procNotifyIPInterfaceChange.Find(); err != nil {
		logger.Debug("NotifyIpInterfaceChange unavailable; using address poll", slog.Any("error", err))
		return nil
	}
	if err := procCancelMibChangeNotify2.Find(); err != nil {
		logger.Debug("CancelMibChangeNotify2 unavailable; using address poll", slog.Any("error", err))
		return nil
	}
	return &winSource{logger: logger}
}

func (s *winSource) watch(ctx context.Context, wake chan<- struct{}) {
	// The OS calls this on a worker thread for every interface change. A
	// non-blocking channel send is safe from any thread and coalesces bursts.
	cb := syscall.NewCallback(func(_ uintptr, _ uintptr, _ uintptr) uintptr {
		select {
		case wake <- struct{}{}:
		default:
		}
		return 0
	})

	var handle uintptr
	// NotifyIpInterfaceChange(Family, Callback, CallerContext, InitialNotification, *Handle)
	// returns NO_ERROR (0) on success.
	r1, _, _ := procNotifyIPInterfaceChange.Call(
		uintptr(afUnspec),
		cb,
		0, // CallerContext, unused
		0, // InitialNotification = FALSE (no spurious first callback)
		uintptr(unsafe.Pointer(&handle)),
	)
	if r1 != 0 {
		// Registration failed; the monitor's safety poll still covers changes.
		s.logger.Debug("NotifyIpInterfaceChange registration failed; relying on safety poll", slog.Uint64("code", uint64(r1)))
		return
	}
	s.handle = handle
	s.hasHandle = true

	<-ctx.Done()
	s.cancel()
}

func (s *winSource) cancel() {
	s.once.Do(func() {
		if s.hasHandle {
			_, _, _ = procCancelMibChangeNotify2.Call(s.handle)
		}
	})
}

func (s *winSource) Close() error {
	s.cancel()
	return nil
}

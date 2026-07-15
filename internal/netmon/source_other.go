//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !windows

package netmon

import "log/slog"

// newSource returns nil on platforms with no implemented event source, so the
// Monitor falls back to its portable 10s address poll. Linux (netlink),
// macOS/BSD (PF_ROUTE), and Windows (NotifyIpInterfaceChange) all have native
// event sources; this covers any remaining GOOS (e.g. plan9, solaris, wasm).
func newSource(_ *slog.Logger) source { return nil }

package security

import "github.com/localport/agent/internal/errcode"

// ErrUnsafeExecutable refuses an executable the device service must not run:
// a path a service definition cannot carry, or a binary that someone other
// than root (SYSTEM, Administrators or TrustedInstaller on Windows) could
// replace. The service runs it as root or as its own account, so a replaced
// binary could widen what the device allows.
var ErrUnsafeExecutable = errcode.New(errcode.UnsafeExecutable)

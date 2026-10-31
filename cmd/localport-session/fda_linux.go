//go:build cgo

package main

import "github.com/localport/agent/internal/launcher"

// fullDiskAccess is a macOS state; Linux reports unknown.
func fullDiskAccess() string { return launcher.FullDiskAccessUnknown }

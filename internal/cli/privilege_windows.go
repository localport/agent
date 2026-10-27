//go:build windows

package cli

import "golang.org/x/sys/windows"

// privileged reports whether the agent runs elevated as an Administrator,
// which owns the machine-wide local config.
func privileged() bool { return windows.GetCurrentProcessToken().IsElevated() }

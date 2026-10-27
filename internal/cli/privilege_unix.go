//go:build !windows

package cli

import "os"

// privileged reports whether the agent runs as root, which owns the
// machine-wide local config.
func privileged() bool { return os.Geteuid() == 0 }

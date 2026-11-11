//go:build !windows

package service

import "context"

// RunUnderSCM reports false: only Windows has a service control manager.
func RunUnderSCM(string, func(ctx context.Context, running func()) error) (bool, error) {
	return false, nil
}

// CrashRoot is "": crash capture is a Windows service feature; the Unix
// service managers keep fatal output in the agent's log (logfile dupOnto
// fd 2) or the journal.
func CrashRoot() string { return "" }

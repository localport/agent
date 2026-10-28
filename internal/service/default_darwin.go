//go:build darwin

package service

// Default is the launchd manager.
func Default() (Manager, error) {
	return launchd{plistPath: LaunchdPlistPath, logPath: launchdLog, logUID: 0, run: execRun}, nil
}

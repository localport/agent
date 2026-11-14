//go:build darwin

package service

// Default is the launchd manager.
func Default() (Manager, error) {
	return launchd{plistPath: LaunchdPlistPath, logDir: launchdAgentLogDir, account: LookupAccount, run: managerRun}, nil
}

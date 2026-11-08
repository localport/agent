//go:build !windows

package cli

// checkSessionAccount has nothing to refuse: the Unix launcher's peer check
// fails per session against the configured agent account.
func checkSessionAccount() error { return nil }

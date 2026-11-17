//go:build !windows

package cli

// processLogin is never called off Windows; currentInvoker uses os/user there.
func processLogin() (login, noDefault string) { return "", "" }

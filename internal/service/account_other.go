//go:build !linux && !darwin

package service

import "context"

// createAccount is unsupported: Windows runs the agent under its service SID.
func createAccount(context.Context, runner, string) error { return ErrUnsupported }

// checkAccountShape accepts any account: there is no account record.
func checkAccountShape(context.Context, runner, Account) error { return nil }

// accountRemoval is nil: there is no account to remove.
func accountRemoval() (usr, group []string) { return nil, nil }

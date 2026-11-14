package service

import (
	"context"
	"errors"
	"os"
	"os/user"
)

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// lookupGroup is groupExists; tests replace it.
var lookupGroup = groupExists

// groupExists reports whether the agent account's group exists.
func groupExists() (bool, error) {
	_, err := user.LookupGroup(AgentAccount)
	var unknown user.UnknownGroupError
	if errors.As(err, &unknown) {
		return false, nil
	}
	return err == nil, err
}

// accountRemoval is the host tool's delete commands: userdel and groupdel, or
// BusyBox deluser and delgroup.
func accountRemoval() (usr, group []string) {
	tool, shadow := accountTool(fileExists)
	if tool == "" {
		return nil, nil
	}
	return deleteCommandsFor(tool, shadow)
}

// createAccount creates the group, when missing, and the user with the
// host's tool.
func createAccount(ctx context.Context, run runner) error {
	tool, shadow := accountTool(fileExists)
	if tool == "" {
		// OpenWrt has neither; its localport package creates the account.
		return errors.New("no useradd or adduser on this host; install the localport package, which creates the account")
	}
	hasGroup, err := lookupGroup()
	if err != nil {
		return err
	}
	group, usr := commandsFor(tool, shadow, hasGroup, nologin(fileExists))
	if group != nil {
		if _, err := run(ctx, group[0], group[1:]...); err != nil {
			// A concurrent install or package postinstall may have created
			// the group since the check; the user is still to be created.
			if exists, lookupErr := lookupGroup(); lookupErr != nil || !exists {
				return err
			}
		}
	}
	_, err = run(ctx, usr[0], usr[1:]...)
	return err
}

package service

import (
	"context"
	"errors"
	"os"
	"os/user"
)

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// groupExists reports whether the agent account's group exists.
func groupExists() (bool, error) {
	_, err := user.LookupGroup(AgentAccount)
	var unknown user.UnknownGroupError
	if errors.As(err, &unknown) {
		return false, nil
	}
	return err == nil, err
}

// createAccount creates the group, when missing, and the user with the
// host's tool.
func createAccount(ctx context.Context, run runner) error {
	tool, shadow := accountTool(fileExists)
	if tool == "" {
		// OpenWrt has neither; its localport package creates the account.
		return errors.New("no useradd or adduser on this host; install the localport package, which creates the account")
	}
	hasGroup, err := groupExists()
	if err != nil {
		return err
	}
	group, usr := commandsFor(tool, shadow, hasGroup, nologin(fileExists))
	if group != nil {
		if _, err := run(ctx, group[0], group[1:]...); err != nil {
			return err
		}
	}
	_, err = run(ctx, usr[0], usr[1:]...)
	return err
}

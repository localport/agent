package service

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

const dsclPath = "/usr/bin/dscl"

// macOS reserves ids below 500 for system accounts; the account takes the
// first id free as both a uid and a gid, searched from accountIDFirst up.
const (
	accountIDFirst = 400
	accountIDLimit = 500
)

// createAccount creates the group and the hidden user with dscl, under one
// id free as both a uid and a gid below 500.
func createAccount(ctx context.Context, run runner) error {
	uids, err := run(ctx, dsclPath, ".", "-list", "/Users", "UniqueID")
	if err != nil {
		return err
	}
	gids, err := run(ctx, dsclPath, ".", "-list", "/Groups", "PrimaryGroupID")
	if err != nil {
		return err
	}
	id, err := freeSystemID(uids, gids)
	if err != nil {
		return err
	}
	ids := strconv.Itoa(id)
	group := "/Groups/" + AgentAccount
	usr := "/Users/" + AgentAccount
	for _, args := range [][]string{
		{".", "-create", group},
		{".", "-create", group, "PrimaryGroupID", ids},
		{".", "-create", group, "Password", "*"},
		{".", "-create", usr},
		{".", "-create", usr, "UniqueID", ids},
		{".", "-create", usr, "PrimaryGroupID", ids},
		{".", "-create", usr, "UserShell", "/usr/bin/false"},
		{".", "-create", usr, "NFSHomeDirectory", "/var/empty"},
		{".", "-create", usr, "RealName", accountDescription},
		{".", "-create", usr, "Password", "*"},
		{".", "-create", usr, "IsHidden", "1"},
	} {
		if _, err := run(ctx, dsclPath, args...); err != nil {
			return err
		}
	}
	return nil
}

// deleteAccount deletes the user, then the group, with dscl.
func deleteAccount(ctx context.Context, run runner) error {
	for _, path := range []string{"/Users/" + AgentAccount, "/Groups/" + AgentAccount} {
		if _, err := run(ctx, dsclPath, ".", "-delete", path); err != nil {
			return err
		}
	}
	return nil
}

// freeSystemID returns the first id in [accountIDFirst, accountIDLimit) that
// is neither a uid nor a gid in the dscl -list outputs.
func freeSystemID(uids, gids string) (int, error) {
	used := map[int]bool{}
	for _, out := range []string{uids, gids} {
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) != 2 {
				continue
			}
			if id, err := strconv.Atoi(f[1]); err == nil {
				used[id] = true
			}
		}
	}
	for id := accountIDFirst; id < accountIDLimit; id++ {
		if !used[id] {
			return id, nil
		}
	}
	return 0, fmt.Errorf("no id between %d and %d is free for the account %s", accountIDFirst, accountIDLimit-1, AgentAccount)
}

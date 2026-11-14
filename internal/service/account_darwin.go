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

// createAccount creates the hidden user with dscl under an id free as both a
// uid and a gid below 500, and its group under the same id. A group of that
// name that already exists keeps its gid, so files it owns keep their group.
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
	var steps [][]string
	gid, found := listedID(gids, AgentAccount)
	if !found {
		gid = id
		steps = [][]string{
			{".", "-create", group},
			{".", "-create", group, "PrimaryGroupID", ids},
			{".", "-create", group, "Password", "*"},
		}
	}
	for _, args := range append(steps, [][]string{
		{".", "-create", usr},
		{".", "-create", usr, "UniqueID", ids},
		{".", "-create", usr, "PrimaryGroupID", strconv.Itoa(gid)},
		{".", "-create", usr, "UserShell", "/usr/bin/false"},
		{".", "-create", usr, "NFSHomeDirectory", "/var/empty"},
		{".", "-create", usr, "RealName", accountDescription},
		{".", "-create", usr, "Password", "*"},
		{".", "-create", usr, "IsHidden", "1"},
	}...) {
		if _, err := run(ctx, dsclPath, args...); err != nil {
			return err
		}
	}
	return nil
}

// accountRemoval is the dscl commands that delete the user and the group.
func accountRemoval() (usr, group []string) {
	return []string{dsclPath, ".", "-delete", "/Users/" + AgentAccount}, []string{dsclPath, ".", "-delete", "/Groups/" + AgentAccount}
}

// dsclIDs parses a `dscl . -list <path> <id key>` output, one "name id" per
// line, skipping lines that are not.
func dsclIDs(out string, each func(name string, id int)) {
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		if id, err := strconv.Atoi(f[1]); err == nil {
			each(f[0], id)
		}
	}
}

// listedID returns the id of name in a dscl -list output.
func listedID(out, name string) (id int, found bool) {
	dsclIDs(out, func(n string, i int) {
		if n == name {
			id, found = i, true
		}
	})
	return id, found
}

// freeSystemID returns the first id in [accountIDFirst, accountIDLimit) that
// is neither a uid nor a gid in the dscl -list outputs.
func freeSystemID(uids, gids string) (int, error) {
	used := map[int]bool{}
	for _, out := range []string{uids, gids} {
		dsclIDs(out, func(_ string, id int) { used[id] = true })
	}
	for id := accountIDFirst; id < accountIDLimit; id++ {
		if !used[id] {
			return id, nil
		}
	}
	return 0, fmt.Errorf("no id between %d and %d is free for the account %s", accountIDFirst, accountIDLimit-1, AgentAccount)
}

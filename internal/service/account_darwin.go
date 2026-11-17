package service

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/localport/agent/internal/errcode"
)

const (
	dsclPath         = "/usr/bin/dscl"
	dsmemberutilPath = "/usr/bin/dsmemberutil"
)

// The account takes an id in [accountIDFirst, accountIDLimit), the range
// sysadminctl documents for role accounts; Apple's own accounts sit below it.
const (
	accountIDFirst = 450
	accountIDLimit = 500
)

// The record fields of an account in the shape of Apple's role accounts
// (_www, _mdnsresponder): no password and no authentication authority, so no
// login of any kind, and no shell.
const (
	accountPassword = "*"
	accountShell    = "/usr/bin/false"
	accountHomeDir  = "/var/empty"
)

// privilegedGroups are the groups the account must not belong to: admin and
// wheel administer the Mac, and staff reaches every user's home directory.
var privilegedGroups = []string{"admin", "wheel", "staff"}

// ownerIDs is the uid and gid that own a file.
type ownerIDs struct{ uid, gid int }

// identityDirOwner returns the owner of an existing identity directory; tests
// replace it.
var identityDirOwner = lstatDirOwner

// lstatDirOwner returns the owner of the directory at path, without following
// a link. Any failure reads as no directory: createAccount then takes fresh
// ids, and ensureIdentityDir adopts an empty directory owned by root and
// refuses any other owner.
func lstatDirOwner(path string) (ownerIDs, bool) {
	fi, err := os.Lstat(path)
	if err != nil || !fi.IsDir() {
		return ownerIDs{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ownerIDs{}, false
	}
	return ownerIDs{uid: int(st.Uid), gid: int(st.Gid)}, true
}

// createAccount creates the hidden user with dscl in the role-account shape,
// with the ids accountIDs picks for it, and its group when missing. A group
// of that name that already exists keeps its gid, so files it owns keep their
// group. It never runs sysadminctl, which writes a ShadowHash and adds the
// account to staff.
func createAccount(ctx context.Context, run runner, identityDir string) error {
	uids, err := run(ctx, dsclPath, ".", "-list", "/Users", "UniqueID")
	if err != nil {
		return err
	}
	gids, err := run(ctx, dsclPath, ".", "-list", "/Groups", "PrimaryGroupID")
	if err != nil {
		return err
	}
	owner, hasOwner := identityDirOwner(identityDir)
	uid, gid, err := accountIDs(uids, gids, owner, hasOwner)
	if err != nil {
		return err
	}
	group := "/Groups/" + AgentAccount
	usr := "/Users/" + AgentAccount
	var steps [][]string
	if _, found := listedID(gids, AgentAccount); !found {
		steps = [][]string{
			{".", "-create", group},
			{".", "-create", group, "PrimaryGroupID", strconv.Itoa(gid)},
			{".", "-create", group, "Password", accountPassword},
		}
	}
	for _, args := range append(steps, [][]string{
		{".", "-create", usr},
		{".", "-create", usr, "UniqueID", strconv.Itoa(uid)},
		{".", "-create", usr, "PrimaryGroupID", strconv.Itoa(gid)},
		{".", "-create", usr, "UserShell", accountShell},
		{".", "-create", usr, "NFSHomeDirectory", accountHomeDir},
		{".", "-create", usr, "RealName", accountDescription},
		{".", "-create", usr, "Password", accountPassword},
		{".", "-create", usr, "IsHidden", "1"},
	}...) {
		if _, err := run(ctx, dsclPath, args...); err != nil {
			return err
		}
	}
	return nil
}

// accountIDs picks the uid and gid of a new account from the dscl -list
// outputs. The uid is the identity directory owner's when that uid lies in
// the account range and no account holds it, so the credentials keep their
// owner and no key material is chowned; otherwise it is the first id free as
// both a uid and a gid. The directory's gid grants nothing (the directory is
// 0700, its files 0600), so it does not decide reuse. An existing agent group
// keeps its gid. A new group takes the first of the directory's gid, the uid
// and a fresh id that lies in the range and is held by no group.
func accountIDs(uids, gids string, owner ownerIDs, hasOwner bool) (uid, gid int, err error) {
	groupGID, groupFound := listedID(gids, AgentAccount)
	if !hasOwner || !inAccountRange(owner.uid) || idListed(uids, owner.uid) {
		id, err := freeSystemID(uids, gids)
		if err != nil {
			return 0, 0, err
		}
		if groupFound {
			return id, groupGID, nil
		}
		return id, id, nil
	}
	if groupFound {
		return owner.uid, groupGID, nil
	}
	for _, id := range []int{owner.gid, owner.uid} {
		if inAccountRange(id) && !idListed(gids, id) {
			return owner.uid, id, nil
		}
	}
	gid, err = freeSystemID(uids, gids)
	return owner.uid, gid, err
}

func inAccountRange(id int) bool { return id >= accountIDFirst && id < accountIDLimit }

// checkAccountShape refuses, with AgentAccountUnsafe, an account that can log
// in or reaches other users' files: an authentication authority, a password
// other than "*", a shell other than /usr/bin/false, a primary group other
// than the agent group, a uid outside the account range, or membership in a
// privileged group. dsmemberutil resolves nested and implicit membership.
// localport never edits an existing account to fit.
func checkAccountShape(ctx context.Context, run runner, acct Account) error {
	out, err := run(ctx, dsclPath, ".", "-read", "/Users/"+AgentAccount)
	if err != nil {
		return errAccount.With(err, "read "+AgentAccount)
	}
	gids, err := run(ctx, dsclPath, ".", "-list", "/Groups", "PrimaryGroupID")
	if err != nil {
		return errAccount.With(err, "list groups")
	}
	rec := dsclRecord(out)
	var unsafe []string
	if _, ok := rec["AuthenticationAuthority"]; ok {
		unsafe = append(unsafe, "it has an AuthenticationAuthority")
	}
	if !slices.Equal(rec["Password"], []string{accountPassword}) {
		unsafe = append(unsafe, "its Password is not "+accountPassword)
	}
	if !slices.Equal(rec["UserShell"], []string{accountShell}) {
		unsafe = append(unsafe, "its shell is not "+accountShell)
	}
	if gid, found := listedID(gids, AgentAccount); !found || gid != acct.GID {
		unsafe = append(unsafe, "its primary group is not "+AgentAccount)
	}
	if !inAccountRange(acct.UID) {
		unsafe = append(unsafe, fmt.Sprintf("its uid %d is outside %d-%d", acct.UID, accountIDFirst, accountIDLimit-1))
	}
	for _, g := range privilegedGroups {
		member, err := isMember(ctx, run, g)
		if err != nil {
			return errAccount.With(err, "check membership in "+g)
		}
		if member {
			unsafe = append(unsafe, "it is a member of "+g)
		}
	}
	if len(unsafe) > 0 {
		return errcode.New(errcode.AgentAccountUnsafe).With(nil, strings.Join(unsafe, "; "))
	}
	return nil
}

// isMember reports whether the agent account is a member of group, from
// dsmemberutil's answer. Any other answer is an error.
func isMember(ctx context.Context, run runner, group string) (bool, error) {
	out, err := run(ctx, dsmemberutilPath, "checkmembership", "-U", AgentAccount, "-G", group)
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(out) {
	case "user is a member of the group":
		return true, nil
	case "user is not a member of the group":
		return false, nil
	}
	return false, fmt.Errorf("dsmemberutil answered %q", strings.TrimSpace(out))
}

// dsclRecord parses `dscl . -read <record>` output into its attributes. A
// line is "Key: values" with values separated by spaces, or "Key:" followed
// by lines indented with a space, one value each. A key with no values is
// present with a nil slice.
func dsclRecord(out string) map[string][]string {
	rec := map[string][]string{}
	key := ""
	for line := range strings.SplitSeq(out, "\n") {
		switch {
		case line == "":
		case line[0] == ' ':
			if key != "" {
				rec[key] = append(rec[key], strings.TrimSpace(line))
			}
		case strings.HasSuffix(line, ":"):
			key = strings.TrimSuffix(line, ":")
			if _, ok := rec[key]; !ok {
				rec[key] = nil
			}
		default:
			k, v, ok := strings.Cut(line, ": ")
			if !ok {
				key = ""
				continue
			}
			key = k
			rec[k] = append(rec[k], strings.Fields(v)...)
		}
	}
	return rec
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

// idListed reports whether any name in a dscl -list output holds id.
func idListed(out string, id int) (listed bool) {
	dsclIDs(out, func(_ string, i int) { listed = listed || i == id })
	return listed
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

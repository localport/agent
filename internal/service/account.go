package service

import (
	"context"
	"errors"
	"fmt"
	"os/user"
	"strconv"
	"strings"

	"github.com/localport/agent/internal/errcode"
)

// errAccount is a failure to create or look up the agent account.
var errAccount = errcode.New(errcode.AccountNotChanged)

// Account is the agent account's ids.
type Account struct {
	UID, GID int
}

// accountDescription is the account's GECOS / RealName.
const accountDescription = "Localport agent"

// accountHome is the Linux account's home, which does not exist.
// packaging/nfpm/sysusers.conf and postinstall.sh create the same account.
const accountHome = "/nonexistent"

// EnsureAccount creates the system group and user AgentAccount when missing
// (no login shell, no home) and returns their ids. It is idempotent, as the
// packages' postinstall is, which creates the same account.
func EnsureAccount(ctx context.Context) (Account, error) {
	return ensureAccount(ctx, execRun, hostAccounts{})
}

// LookupAccount returns the agent account's ids, or an error naming it when
// it does not exist.
func LookupAccount() (Account, error) { return lookupAccount(hostAccounts{}) }

// accounts reads the local account database; tests replace it.
type accounts interface {
	lookup(name string) (uid, gid int, found bool, err error)
}

// hostAccounts reads the account database through os/user: /etc/passwd on
// Linux without cgo (system accounts are local on every host the agent runs
// on), Directory Services through libSystem on macOS.
type hostAccounts struct{}

func (hostAccounts) lookup(name string) (int, int, bool, error) {
	u, err := user.Lookup(name)
	var unknown user.UnknownUserError
	if errors.As(err, &unknown) {
		return 0, 0, false, nil
	}
	if err != nil {
		return 0, 0, false, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, false, fmt.Errorf("account %s: uid %q: %w", name, u.Uid, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, false, fmt.Errorf("account %s: gid %q: %w", name, u.Gid, err)
	}
	return uid, gid, true, nil
}

func lookupAccount(db accounts) (Account, error) {
	uid, gid, found, err := db.lookup(AgentAccount)
	if err != nil {
		return Account{}, errAccount.With(err, "look up "+AgentAccount)
	}
	if !found {
		return Account{}, errcode.New(errcode.AccountMissing).With(nil, "")
	}
	return Account{UID: uid, GID: gid}, nil
}

func ensureAccount(ctx context.Context, run runner, db accounts) (Account, error) {
	if _, _, found, err := db.lookup(AgentAccount); err != nil {
		return Account{}, errAccount.With(err, "look up "+AgentAccount)
	} else if !found {
		if err := createAccount(ctx, run); err != nil {
			// A concurrent install or package postinstall may have created
			// it between the lookup and the create.
			if acct, lookupErr := lookupAccount(db); lookupErr == nil {
				return acct, nil
			}
			return Account{}, errAccount.With(err, "create "+AgentAccount)
		}
	}
	return lookupAccount(db)
}

// AccountRemoval returns the commands that delete the user and the group
// AgentAccount, for an administrator who wants them gone, or nil where the
// host has no tool for it (OpenWrt's default BusyBox; its package owns the
// account). localport never deletes the account, as distributions and
// systemd-sysusers do not: a file it owns outside localport's directories
// would pass to a later account that reuses the uid or gid.
func AccountRemoval() (usr, group []string) { return accountRemoval() }

// deleteCommandsFor are the commands that delete the user and its group,
// the counterparts of commandsFor.
func deleteCommandsFor(tool string, shadow bool) (usr, group []string) {
	if shadow {
		dir := strings.TrimSuffix(tool, "useradd")
		return []string{dir + "userdel", AgentAccount}, []string{dir + "groupdel", AgentAccount}
	}
	dir := strings.TrimSuffix(tool, "adduser")
	return []string{dir + "deluser", AgentAccount}, []string{dir + "delgroup", AgentAccount}
}

// accountTool picks the first tool present: shadow's useradd, or BusyBox
// adduser (Alpine without shadow). OpenWrt's default BusyBox has neither.
func accountTool(exists func(string) bool) (string, bool) {
	for _, p := range []string{"/usr/sbin/useradd", "/sbin/useradd"} {
		if exists(p) {
			return p, true
		}
	}
	for _, p := range []string{"/usr/sbin/adduser", "/sbin/adduser", "/bin/adduser"} {
		if exists(p) {
			return p, false
		}
	}
	return "", false
}

// nologin is the account's shell: the first of the hosts' nologin paths.
func nologin(exists func(string) bool) string {
	for _, p := range []string{"/usr/sbin/nologin", "/sbin/nologin"} {
		if exists(p) {
			return p
		}
	}
	return "/bin/false"
}

// commandsFor are the commands that create the group (nil when it exists)
// and the user with tool.
func commandsFor(tool string, shadow, groupExists bool, shell string) (group, usr []string) {
	if shadow {
		if !groupExists {
			group = []string{strings.TrimSuffix(tool, "useradd") + "groupadd", "--system", AgentAccount}
		}
		return group, []string{tool, "--system", "--gid", AgentAccount, "--no-create-home", "--home-dir", accountHome,
			"--shell", shell, "--comment", accountDescription, AgentAccount}
	}
	if !groupExists {
		group = []string{strings.TrimSuffix(tool, "adduser") + "addgroup", "-S", AgentAccount}
	}
	return group, []string{tool, "-S", "-D", "-H", "-h", accountHome, "-s", shell, "-G", AgentAccount, "-g", accountDescription, AgentAccount}
}

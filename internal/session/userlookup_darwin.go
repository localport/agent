package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/localport/agent/internal/errcode"
)

// errLookupPending refuses a lookup while an earlier one has not returned.
var errLookupPending = errcode.New(errcode.LookupPending)

// directoryLookup resolves accounts through os/user, which calls libc
// (getpwnam_r, getgrouplist) without cgo and so sees directory users. A
// blocked libc call cannot be cancelled, so at most one runs at a time: a
// lookup whose deadline passes returns while its call keeps running, and
// every lookup until that call returns is refused.
type directoryLookup struct {
	// resolve performs the blocking lookup.
	resolve func(login string) (*userRecord, error)
	// shell returns the login shell after resolve, "" for none. It runs in
	// the same in-flight slot. Optional.
	shell func(ctx context.Context, login string) (string, error)

	// mu guards pending.
	mu      sync.Mutex
	pending bool
}

var systemUsers = &directoryLookup{resolve: resolveDirectoryUser, shell: agentUserShell}

// dsclPath is the directory service tool that gives the login shell.
const dsclPath = "/usr/bin/dscl"

// agentUserShell returns the login shell the direct exec runs, which only a
// non-root agent uses: as root, login(1) starts the shell.
func agentUserShell(ctx context.Context, login string) (string, error) {
	if os.Geteuid() == 0 {
		return "", nil
	}
	return loginShell(ctx, dsclPath, login)
}

// loginShell reads login's UserShell through dscl, run as runLookupTool runs
// its tools. No value or an unparsable one is "", which runs /bin/sh; a
// timeout, a failed run or a non-zero status is an error.
func loginShell(ctx context.Context, tool, login string) (string, error) {
	out, status, err := runLookupTool(ctx, tool, "/Search", "-read", "/Users/"+login, "UserShell")
	if err != nil {
		return "", err
	}
	if status != 0 {
		return "", fmt.Errorf("dscl exited with status %d", status)
	}
	return parseUserShell(out), nil
}

// parseUserShell accepts exactly one line "UserShell: <path>" with a clean
// absolute path and no spaces; anything else is "".
func parseUserShell(out []byte) string {
	line, rest, _ := strings.Cut(strings.TrimSuffix(string(out), "\n"), "\n")
	v, ok := strings.CutPrefix(line, "UserShell: ")
	if !ok || rest != "" || !filepath.IsAbs(v) || filepath.Clean(v) != v || strings.ContainsAny(v, " \t") {
		return ""
	}
	return v
}

// lookupUser resolves login through the system's directory services.
func lookupUser(ctx context.Context, login string) (*userRecord, error) {
	return systemUsers.lookup(ctx, login)
}

func (d *directoryLookup) lookup(ctx context.Context, login string) (*userRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("directory lookup: no time left: %w", err)
	}
	d.mu.Lock()
	if d.pending {
		d.mu.Unlock()
		return nil, errLookupPending
	}
	d.pending = true
	d.mu.Unlock()

	type result struct {
		user *userRecord
		err  error
	}
	done := make(chan result, 1)
	go func() {
		u, err := d.resolve(login)
		if err == nil && d.shell != nil {
			u.Shell, err = d.shell(ctx, login)
			if err != nil {
				u = nil
			}
		}
		d.mu.Lock()
		d.pending = false
		d.mu.Unlock()
		done <- result{u, err}
	}()
	select {
	case r := <-done:
		return r.user, r.err
	case <-ctx.Done():
		return nil, fmt.Errorf("directory lookup timed out: %w", ctx.Err())
	}
}

// resolveDirectoryUser returns login's account and group list. os/user gives
// no login shell, so Shell is empty; directoryLookup.shell sets it.
func resolveDirectoryUser(login string) (*userRecord, error) {
	u, err := user.Lookup(login)
	if errors.As(err, new(user.UnknownUserError)) {
		return nil, errNoUser
	}
	if err != nil {
		return nil, fmt.Errorf("directory lookup: %w", err)
	}
	if u.Username != login {
		return nil, errNoUser
	}
	uid, err := parseDirectoryID(u.Uid)
	if err != nil {
		return nil, err
	}
	gid, err := parseDirectoryID(u.Gid)
	if err != nil {
		return nil, err
	}
	ids, err := u.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("directory group lookup: %w", err)
	}
	groups := []uint32{gid}
	for _, s := range ids {
		g, err := parseDirectoryID(s)
		if err != nil {
			return nil, err
		}
		if g != gid {
			groups = append(groups, g)
		}
	}
	return &userRecord{Name: login, UID: uid, GID: gid, Groups: groups, Home: u.HomeDir}, nil
}

func parseDirectoryID(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("directory lookup: %q is not a numeric id", s)
	}
	return uint32(n), nil
}

package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
)

// getentLookup resolves accounts through NSS with getent, so directory users
// (LDAP, SSSD, systemd-homed) resolve as they do for login. Where no getent
// exists it parses the account files, which is exact on systems without NSS.
type getentLookup struct {
	// getent lists the candidate getent paths in order; the first that
	// exists is run.
	getent []string
	passwd string
	group  string
}

var systemUsers = &getentLookup{
	getent: []string{"/usr/bin/getent", "/bin/getent"},
	passwd: "/etc/passwd",
	group:  "/etc/group",
}

// lookupUser resolves login through the system's account databases.
func lookupUser(ctx context.Context, login string) (*userRecord, error) {
	return systemUsers.lookup(ctx, login)
}

func (g *getentLookup) lookup(ctx context.Context, login string) (*userRecord, error) {
	tool, err := g.tool()
	if err != nil {
		return nil, err
	}
	if tool == "" {
		return g.lookupFiles(login)
	}
	out, status, err := runLookupTool(ctx, tool, "passwd", login)
	if err != nil {
		return nil, err
	}
	if err := getentStatus("passwd", status); err != nil {
		return nil, err
	}
	user, err := parsePasswdEntry(out, login)
	if err != nil {
		return nil, err
	}

	out, status, err = runLookupTool(ctx, tool, "initgroups", login)
	if err != nil {
		return nil, err
	}
	var groups []uint32
	if status == 1 {
		// initgroups is unsupported (musl): filter the group database.
		if out, status, err = runLookupTool(ctx, tool, "group"); err != nil {
			return nil, err
		}
		if err := getentStatus("group", status); err != nil {
			return nil, err
		}
		entries, err := parseGroupFile(out)
		if err != nil {
			return nil, fmt.Errorf("getent group: %w", err)
		}
		groups = memberGroups(entries, login)
	} else {
		if err := getentStatus("initgroups", status); err != nil {
			return nil, err
		}
		if groups, err = parseInitgroups(out, login); err != nil {
			return nil, err
		}
	}
	user.Groups = withPrimaryGroup(groups, user.GID)
	return user, nil
}

// tool returns the first getent path that exists, or "" when none does.
func (g *getentLookup) tool() (string, error) {
	for _, p := range g.getent {
		_, err := os.Stat(p)
		if err == nil {
			return p, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("getent: %w", err)
		}
	}
	return "", nil
}

// getentStatus maps a getent exit status: 0 found, 2 no entry, any other a
// failure.
func getentStatus(db string, status int) error {
	switch status {
	case 0:
		return nil
	case 2:
		return errNoUser
	}
	return fmt.Errorf("getent %s exited with status %d", db, status)
}

// lookupFiles resolves login from the passwd and group files.
func (g *getentLookup) lookupFiles(login string) (*userRecord, error) {
	passwd, err := readBounded(g.passwd)
	if err != nil {
		return nil, err
	}
	user, err := findPasswdEntry(passwd, login)
	if err != nil {
		return nil, err
	}
	group, err := readBounded(g.group)
	if err != nil {
		return nil, err
	}
	entries, err := parseGroupFile(group)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", g.group, err)
	}
	user.Groups = withPrimaryGroup(memberGroups(entries, login), user.GID)
	return user, nil
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxLookupOutput+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxLookupOutput {
		return nil, fmt.Errorf("%s: %w", path, errLookupOutputTooLarge)
	}
	return data, nil
}

// parsePasswdEntry parses getent's answer for login: exactly one passwd
// line naming login.
func parsePasswdEntry(out []byte, login string) (*userRecord, error) {
	line, ok := singleLine(out)
	if !ok {
		return nil, errors.New("getent passwd: not exactly one line")
	}
	user, err := parsePasswdLine(line)
	if err != nil {
		return nil, fmt.Errorf("getent passwd: %w", err)
	}
	if user.Name != login {
		return nil, fmt.Errorf("getent passwd: entry names %q, not the login", user.Name)
	}
	return user, nil
}

// findPasswdEntry returns login's entry from a passwd file. Every line must
// be well formed.
func findPasswdEntry(data []byte, login string) (*userRecord, error) {
	var found *userRecord
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSuffix(line, "\n")
		if line == "" {
			continue
		}
		user, err := parsePasswdLine(line)
		if err != nil {
			return nil, fmt.Errorf("passwd file: %w", err)
		}
		if user.Name == login && found == nil {
			found = user
		}
	}
	if found == nil {
		return nil, errNoUser
	}
	return found, nil
}

// parsePasswdLine parses name:password:uid:gid:gecos:home:shell.
func parsePasswdLine(line string) (*userRecord, error) {
	f := strings.Split(line, ":")
	if len(f) != 7 {
		return nil, fmt.Errorf("passwd line has %d fields, want 7", len(f))
	}
	uid, err := parseID(f[2])
	if err != nil {
		return nil, fmt.Errorf("passwd uid: %w", err)
	}
	gid, err := parseID(f[3])
	if err != nil {
		return nil, fmt.Errorf("passwd gid: %w", err)
	}
	return &userRecord{Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: f[6]}, nil
}

// parseInitgroups parses getent initgroups' answer: login, then its gids.
func parseInitgroups(out []byte, login string) ([]uint32, error) {
	line, ok := singleLine(out)
	if !ok {
		return nil, errors.New("getent initgroups: not exactly one line")
	}
	f := strings.Fields(line)
	if len(f) == 0 || f[0] != login {
		return nil, errors.New("getent initgroups: answer does not name the login")
	}
	gids := make([]uint32, 0, len(f)-1)
	for _, s := range f[1:] {
		gid, err := parseID(s)
		if err != nil {
			return nil, fmt.Errorf("getent initgroups: %w", err)
		}
		gids = append(gids, gid)
	}
	return gids, nil
}

// groupEntry is one line of the group database.
type groupEntry struct {
	gid     uint32
	members []string
}

// parseGroupFile parses name:password:gid:member,member lines.
func parseGroupFile(data []byte) ([]groupEntry, error) {
	var entries []groupEntry
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSuffix(line, "\n")
		if line == "" {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) != 4 {
			return nil, fmt.Errorf("group line has %d fields, want 4", len(f))
		}
		gid, err := parseID(f[2])
		if err != nil {
			return nil, fmt.Errorf("group gid: %w", err)
		}
		e := groupEntry{gid: gid}
		if f[3] != "" {
			e.members = strings.Split(f[3], ",")
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// memberGroups returns the gids of the groups that list login as a member.
func memberGroups(entries []groupEntry, login string) []uint32 {
	var gids []uint32
	for _, e := range entries {
		if slices.Contains(e.members, login) {
			gids = append(gids, e.gid)
		}
	}
	return gids
}

// withPrimaryGroup returns primary followed by groups without duplicates.
func withPrimaryGroup(groups []uint32, primary uint32) []uint32 {
	out := []uint32{primary}
	for _, g := range groups {
		if !slices.Contains(out, g) {
			out = append(out, g)
		}
	}
	return out
}

// singleLine returns out without its final newline when out is exactly one
// non-empty line.
func singleLine(out []byte) (string, bool) {
	line, ok := bytes.CutSuffix(out, []byte("\n"))
	if !ok || len(line) == 0 || bytes.ContainsAny(line, "\n\r") {
		return "", false
	}
	return string(line), true
}

// parseID parses a decimal uid or gid.
func parseID(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%q is not a numeric id", s)
	}
	return uint32(n), nil
}

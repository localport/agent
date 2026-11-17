package service

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/localport/agent/internal/errcode"
)

const (
	listUsers  = dsclPath + " . -list /Users UniqueID"
	listGroups = dsclPath + " . -list /Groups PrimaryGroupID"
	readUser   = dsclPath + " . -read /Users/" + AgentAccount
)

// noIdentityDir makes createAccount see no identity directory until the test
// ends.
func noIdentityDir(t *testing.T) { withIdentityDirOwner(t, ownerIDs{}, false) }

func withIdentityDirOwner(t *testing.T, owner ownerIDs, found bool) {
	prev := identityDirOwner
	identityDirOwner = func(string) (ownerIDs, bool) { return owner, found }
	t.Cleanup(func() { identityDirOwner = prev })
}

// createAccount writes exactly the role-account record with dscl, under the
// first id free as both a uid and a gid in 450-499, and never runs
// sysadminctl. A group named like the account keeps its gid: createAccount
// does not create or renumber it and gives the user that gid.
func TestCreateAccountWritesTheRoleAccountShape(t *testing.T) {
	noIdentityDir(t)
	usr := dsclPath + " . -create /Users/" + AgentAccount
	group := dsclPath + " . -create /Groups/" + AgentAccount
	userSteps := func(gid string) []string {
		return []string{
			usr,
			usr + " UniqueID 450",
			usr + " PrimaryGroupID " + gid,
			usr + " UserShell /usr/bin/false",
			usr + " NFSHomeDirectory /var/empty",
			usr + " RealName " + accountDescription,
			usr + " Password *",
			usr + " IsHidden 1",
		}
	}
	for name, tc := range map[string]struct {
		groups string
		want   []string
	}{
		"existing group": {groups: "wheel 0\n" + AgentAccount + " 470\n", want: userSteps("470")},
		"no group": {groups: "wheel 0\n", want: append([]string{
			group,
			group + " PrimaryGroupID 450",
			group + " Password *",
		}, userSteps("450")...)},
	} {
		r := &recorder{out: map[string]string{listUsers: "root 0\n_www 70\n", listGroups: tc.groups}}
		if err := createAccount(context.Background(), r.run, "/identity"); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if want := append([]string{listUsers, listGroups}, tc.want...); !slices.Equal(r.calls, want) {
			t.Errorf("%s: calls\n%q\nwant\n%q", name, r.calls, want)
		}
	}
}

// A recreated account takes the identity directory's ids, so the
// credentials in it keep their owner.
func TestCreateAccountReusesTheIdentityDirOwner(t *testing.T) {
	withIdentityDirOwner(t, ownerIDs{uid: 480, gid: 480}, true)
	r := &recorder{out: map[string]string{listUsers: "root 0\n", listGroups: "wheel 0\n"}}
	if err := createAccount(context.Background(), r.run, "/identity"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		dsclPath + " . -create /Groups/" + AgentAccount + " PrimaryGroupID 480",
		dsclPath + " . -create /Users/" + AgentAccount + " UniqueID 480",
		dsclPath + " . -create /Users/" + AgentAccount + " PrimaryGroupID 480",
	} {
		if !slices.Contains(r.calls, want) {
			t.Errorf("calls %q lack %q", r.calls, want)
		}
	}
}

func TestAccountIDs(t *testing.T) {
	const users = "root 0\n_www 70\nother 470\n"
	for name, tc := range map[string]struct {
		groups   string
		owner    ownerIDs
		hasOwner bool
		uid, gid int
	}{
		"no identity directory":           {groups: "wheel 0\n", uid: 450, gid: 450},
		"unassigned in-range owner":       {groups: "wheel 0\n", owner: ownerIDs{480, 481}, hasOwner: true, uid: 480, gid: 481},
		"owner gid is the agent group":    {groups: AgentAccount + " 490\n", owner: ownerIDs{480, 490}, hasOwner: true, uid: 480, gid: 490},
		"owner gid free, group exists":    {groups: AgentAccount + " 490\n", owner: ownerIDs{480, 485}, hasOwner: true, uid: 480, gid: 490},
		"uid assigned to another account": {groups: "wheel 0\n", owner: ownerIDs{470, 470}, hasOwner: true, uid: 450, gid: 450},
		"uid below the range":             {groups: "wheel 0\n", owner: ownerIDs{401, 401}, hasOwner: true, uid: 450, gid: 450},
		"uid above the range":             {groups: "wheel 0\n", owner: ownerIDs{501, 501}, hasOwner: true, uid: 450, gid: 450},
		"root-owned directory":            {groups: "wheel 0\n", owner: ownerIDs{0, 0}, hasOwner: true, uid: 450, gid: 450},
		"owner gid held, group exists":    {groups: AgentAccount + " 490\nstaff 20\n", owner: ownerIDs{480, 20}, hasOwner: true, uid: 480, gid: 490},
		"owner gid held, no group":        {groups: "wheel 0\nstaff 20\nmine 481\n", owner: ownerIDs{480, 481}, hasOwner: true, uid: 480, gid: 480},
		"owner gid outside the range":     {groups: "wheel 0\n", owner: ownerIDs{480, 1234}, hasOwner: true, uid: 480, gid: 480},
		"owner gid and uid held as gids":  {groups: "wheel 0\nmine 481\nyours 480\n", owner: ownerIDs{480, 481}, hasOwner: true, uid: 480, gid: 450},
	} {
		uid, gid, err := accountIDs(users, tc.groups, tc.owner, tc.hasOwner)
		if err != nil || uid != tc.uid || gid != tc.gid {
			t.Errorf("%s: accountIDs = %d, %d, %v; want %d, %d", name, uid, gid, err, tc.uid, tc.gid)
		}
	}
}

func TestFreeSystemID(t *testing.T) {
	uids := "root 0\n_www 70\ntaken 450\n"
	gids := "wheel 0\ngroup451 451\nmalformed\n"
	if id, err := freeSystemID(uids, gids); err != nil || id != 452 {
		t.Fatalf("freeSystemID = %d, %v, want 452", id, err)
	}
	var all string
	for id := accountIDFirst; id < accountIDLimit; id++ {
		all += "u " + strconv.Itoa(id) + "\n"
	}
	if _, err := freeSystemID(all, ""); err == nil {
		t.Fatal("freeSystemID found an id with every one taken")
	}
}

// inShapeRecord is `dscl . -read` of an account createAccount wrote.
const inShapeRecord = `AppleMetaNodeLocation: /Local/Default
GeneratedUID: 5B0E6F3A-1C2D-4E5F-8A9B-0C1D2E3F4A5B
dsAttrTypeNative:IsHidden: 1
NFSHomeDirectory: /var/empty
Password: *
PrimaryGroupID: 460
RealName:
 Localport agent
RecordName: _localport
RecordType: dsRecTypeStandard:Users
UniqueID: 460
UserShell: /usr/bin/false
`

// accountDB answers the shape check's dscl and dsmemberutil commands.
type accountDB struct {
	record  string
	groups  string
	members []string
	member  string // dsmemberutil's answer for members, when not the usual one
}

func (db accountDB) run(_ context.Context, name string, args ...string) (string, error) {
	call := strings.Join(append([]string{name}, args...), " ")
	switch call {
	case readUser:
		return db.record, nil
	case listGroups:
		return db.groups, nil
	}
	if name == dsmemberutilPath && len(args) == 5 && args[0] == "checkmembership" && args[2] == AgentAccount {
		if !slices.Contains(db.members, args[4]) {
			return "user is not a member of the group\n", nil
		}
		if db.member != "" {
			return db.member, nil
		}
		return "user is a member of the group\n", nil
	}
	return "", errors.New("unexpected command " + call)
}

func TestCheckAccountShape(t *testing.T) {
	inShape := Account{UID: 460, GID: 460}
	groups := "wheel 0\nstaff 20\n" + AgentAccount + " 460\n"
	if err := checkAccountShape(context.Background(), accountDB{record: inShapeRecord, groups: groups}.run, inShape); err != nil {
		t.Fatalf("in-shape account refused: %v", err)
	}
	replace := func(old, repl string) string { return strings.Replace(inShapeRecord, old, repl, 1) }
	for name, tc := range map[string]struct {
		db     accountDB
		acct   Account
		reason string
	}{
		"authentication authority": {db: accountDB{record: inShapeRecord + "AuthenticationAuthority: ;ShadowHash;\n"}, reason: "AuthenticationAuthority"},
		"multi-line authority": {db: accountDB{record: inShapeRecord + "AuthenticationAuthority:\n ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>\n ;Kerberosv5;;_localport@LKDC\n"},
			reason: "AuthenticationAuthority"},
		"password hash":      {db: accountDB{record: replace("Password: *", "Password: ********")}, reason: "Password"},
		"no password":        {db: accountDB{record: replace("Password: *\n", "")}, reason: "Password"},
		"login shell":        {db: accountDB{record: replace("UserShell: /usr/bin/false", "UserShell: /bin/zsh")}, reason: "shell"},
		"primary group":      {db: accountDB{record: inShapeRecord}, acct: Account{UID: 460, GID: 20}, reason: "primary group"},
		"no agent group":     {db: accountDB{record: inShapeRecord, groups: "wheel 0\nstaff 20\n"}, reason: "primary group"},
		"uid below range":    {db: accountDB{record: inShapeRecord}, acct: Account{UID: 401, GID: 460}, reason: "uid 401"},
		"uid above range":    {db: accountDB{record: inShapeRecord}, acct: Account{UID: 501, GID: 460}, reason: "uid 501"},
		"member of admin":    {db: accountDB{record: inShapeRecord, members: []string{"admin"}}, reason: "member of admin"},
		"member of wheel":    {db: accountDB{record: inShapeRecord, members: []string{"wheel"}}, reason: "member of wheel"},
		"member of staff":    {db: accountDB{record: inShapeRecord, members: []string{"staff"}}, reason: "member of staff"},
		"several conditions": {db: accountDB{record: replace("UserShell: /usr/bin/false", "UserShell: /bin/sh"), members: []string{"staff"}}, reason: "shell is not /usr/bin/false; it is a member of staff"},
	} {
		if tc.db.groups == "" {
			tc.db.groups = groups
		}
		if tc.acct == (Account{}) {
			tc.acct = inShape
		}
		err := checkAccountShape(context.Background(), tc.db.run, tc.acct)
		var coded *errcode.Error
		if !errors.As(err, &coded) || coded.Code != errcode.AgentAccountUnsafe || !strings.Contains(coded.Detail, tc.reason) {
			t.Errorf("%s: checkAccountShape = %v, want AG147 naming %q", name, err, tc.reason)
		}
	}
}

// A shape that cannot be read is AG138, never a pass: a failed dscl read or
// a dsmemberutil answer that is neither member nor non-member.
func TestCheckAccountShapeFailsClosed(t *testing.T) {
	inShape := Account{UID: 460, GID: 460}
	groups := AgentAccount + " 460\n"
	for name, run := range map[string]runner{
		"unreadable record": func(context.Context, string, ...string) (string, error) { return "", errors.New("eDSRecordNotFound") },
		"unknown answer":    accountDB{record: inShapeRecord, groups: groups, members: []string{"staff"}, member: "There was an unknown error.\n"}.run,
	} {
		err := checkAccountShape(context.Background(), run, inShape)
		if !errors.Is(err, errcode.New(errcode.AccountNotChanged)) {
			t.Errorf("%s: checkAccountShape = %v, want AG138", name, err)
		}
	}
}

func TestDsclRecord(t *testing.T) {
	rec := dsclRecord(inShapeRecord + "AuthenticationAuthority:\n ;ShadowHash;\nEmpty:\n")
	for key, want := range map[string][]string{
		"Password":                  {"*"},
		"UserShell":                 {"/usr/bin/false"},
		"RealName":                  {"Localport agent"},
		"dsAttrTypeNative:IsHidden": {"1"},
		"AuthenticationAuthority":   {";ShadowHash;"},
	} {
		if got := rec[key]; !slices.Equal(got, want) {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if v, ok := rec["Empty"]; !ok || v != nil {
		t.Errorf("Empty = %q, %v; want present with no values", v, ok)
	}
}

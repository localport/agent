package service

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// A group named like the account keeps its gid: createAccount does not
// create or renumber it and gives the user that gid; without one, the group
// is created under the user's id.
func TestCreateAccountKeepsAnExistingGroupID(t *testing.T) {
	listUsers := dsclPath + " . -list /Users UniqueID"
	listGroups := dsclPath + " . -list /Groups PrimaryGroupID"
	for name, tc := range map[string]struct {
		groups            string
		wantGID           string
		wantGroupCommands bool
	}{
		"existing group": {groups: "wheel 0\n" + AgentAccount + " 450\n", wantGID: "450"},
		"no group":       {groups: "wheel 0\n", wantGID: "400", wantGroupCommands: true},
	} {
		r := &recorder{out: map[string]string{listUsers: "root 0\n", listGroups: tc.groups}}
		if err := createAccount(context.Background(), r.run); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		groupPath := "/Groups/" + AgentAccount
		touchesGroup := slices.ContainsFunc(r.calls, func(c string) bool { return strings.Contains(c, " "+groupPath) })
		if touchesGroup != tc.wantGroupCommands {
			t.Errorf("%s: group commands run = %v, want %v (%q)", name, touchesGroup, tc.wantGroupCommands, r.calls)
		}
		wantUser := dsclPath + " . -create /Users/" + AgentAccount + " PrimaryGroupID " + tc.wantGID
		if !slices.Contains(r.calls, wantUser) {
			t.Errorf("%s: calls %q lack %q", name, r.calls, wantUser)
		}
		if want := dsclPath + " . -create /Users/" + AgentAccount + " UniqueID 400"; !slices.Contains(r.calls, want) {
			t.Errorf("%s: calls %q lack %q", name, r.calls, want)
		}
	}
}

func TestFreeSystemID(t *testing.T) {
	uids := "root 0\n_www 70\ntaken 400\n"
	gids := "wheel 0\ngroup401 401\nmalformed\n"
	if id, err := freeSystemID(uids, gids); err != nil || id != 402 {
		t.Fatalf("freeSystemID = %d, %v, want 402", id, err)
	}
	var all string
	for id := accountIDFirst; id < accountIDLimit; id++ {
		all += "u " + strconv.Itoa(id) + "\n"
	}
	if _, err := freeSystemID(all, ""); err == nil {
		t.Fatal("freeSystemID found an id with every one taken")
	}
}

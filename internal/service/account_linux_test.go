package service

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A group created by a concurrent installer between the check and the group
// command still gets the user created; a group command failure with the
// group still missing is the create's error.
func TestCreateAccountAfterAConcurrentGroupCreate(t *testing.T) {
	if tool, _ := accountTool(fileExists); tool == "" {
		t.Skip("no useradd or adduser on this host")
	}
	for _, tc := range []struct {
		name           string
		existsAfter    bool
		wantUserCreate bool
	}{
		{"raced group", true, true},
		{"group still missing", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookups := 0
			prev := lookupGroup
			lookupGroup = func() (bool, error) { lookups++; return lookups > 1 && tc.existsAfter, nil }
			t.Cleanup(func() { lookupGroup = prev })

			exists := errors.New("group already exists")
			userCreated := false
			run := func(_ context.Context, name string, _ ...string) (string, error) {
				if strings.HasSuffix(name, "groupadd") || strings.HasSuffix(name, "addgroup") {
					return "", exists
				}
				userCreated = true
				return "", nil
			}
			err := createAccount(context.Background(), run)
			if userCreated != tc.wantUserCreate || (err == nil) != tc.wantUserCreate {
				t.Fatalf("createAccount = %v, user created %v; want user created %v", err, userCreated, tc.wantUserCreate)
			}
		})
	}
}

package securitytest

import (
	"fmt"
	"testing"
)

// recorder is a testing.TB that records a failure instead of ending the
// test, so the assertion's own verdict can be checked.
type recorder struct {
	testing.TB
	failure string
}

func (r *recorder) Helper() {}
func (r *recorder) Fatal(args ...any) {
	if r.failure == "" {
		r.failure = fmt.Sprint(args...)
	}
}
func (r *recorder) Fatalf(format string, args ...any) {
	if r.failure == "" {
		r.failure = fmt.Sprintf(format, args...)
	}
}

// RequireOwnerOnly passes a directory only its owner can reach and fails one
// another trustee can read.
func TestRequireOwnerOnly(t *testing.T) {
	private, shared := ownerOnlyDir(t), sharedDir(t)
	r := &recorder{TB: t}
	RequireOwnerOnly(r, private)
	if r.failure != "" {
		t.Fatalf("an owner-only directory failed: %s", r.failure)
	}
	r = &recorder{TB: t}
	RequireOwnerOnly(r, shared)
	if r.failure == "" {
		t.Fatalf("%s, readable by another trustee, passed", shared)
	}
}

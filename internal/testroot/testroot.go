// Package testroot gates the tests that need root (or an elevated
// Administrator) and a test login. Locally a missing precondition skips the
// test; CI sets RequireEnv=1, where a missing precondition fails it, so a
// root test can never pass by being skipped.
package testroot

import (
	"os"
	"testing"
)

// RequireEnv is the variable that turns a missing precondition into a
// failure.
const RequireEnv = "LOCALPORT_REQUIRE_ROOT_TESTS"

// Require ends the test for a precondition it lacks, named for the reader
// ("needs root", "set LOCALPORT_TEST_LOGIN"): a skip, or a failure under
// RequireEnv=1. The caller calls it only when the precondition is missing.
func Require(t testing.TB, precondition string) {
	t.Helper()
	if os.Getenv(RequireEnv) == "1" {
		t.Fatalf("%s=1 and the test lacks its precondition: %s", RequireEnv, precondition)
	}
	t.Skip(precondition)
}

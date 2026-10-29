package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/localport/agent/internal/identity"
)

// hangupSentinelToken is a join token that a connect system log record must
// not hold.
const hangupSentinelToken = "lpj_hangup-sentinel"

// recordSystemLog captures the system log records of the test's commands.
func recordSystemLog(t *testing.T) *[]string {
	t.Helper()
	var lines []string
	systemLog = func(_ bool, line string) { lines = append(lines, line) }
	return &lines
}

// A hangup-safe command records its outcome only when it runs as root: a
// non-root run, and a root run refused at its flags, leave no record.
func TestHangupSafeCommandsLogOnlyAsRoot(t *testing.T) {
	for _, c := range []struct {
		name string
		root bool
		run  func() error
		want []string
	}{
		{name: "non-root service install", run: func() error { return runService([]string{"install"}) }},
		{name: "non-root service uninstall", run: func() error { return runService([]string{"uninstall"}) }},
		{name: "set flag error", root: true, run: func() error { return runSet([]string{"factory.gw-01", "--bogus"}) }},
		{name: "service flag error", root: true, run: func() error { return runService([]string{"uninstall", "--bogus"}) }},
		{name: "root service install", root: true, run: func() error { return runService([]string{"install"}) }, want: []string{"localport service install: failed: "}},
	} {
		t.Run(c.name, func(t *testing.T) {
			asRoot(t, &fakeManager{})
			if !c.root {
				privilegedProcess = func() bool { return false }
			}
			lines := recordSystemLog(t)
			if err := c.run(); err == nil {
				t.Fatal("the command succeeded, want a refusal")
			}
			if len(*lines) != len(c.want) {
				t.Fatalf("system log %q, want %d records", *lines, len(c.want))
			}
			for i, prefix := range c.want {
				if !strings.HasPrefix((*lines)[i], prefix) {
					t.Fatalf("system log %q, want %q first", (*lines)[i], prefix)
				}
			}
		})
	}
}

// The record of a privileged connect that failed names the command and the
// outcome only: neither the join token nor the error text, which can quote
// the arguments.
func TestConnectRecordHoldsNoArgument(t *testing.T) {
	asRoot(t, &fakeManager{})
	lines := recordSystemLog(t)
	fakeEnrol(t, deviceRef("factory.gw-01"))
	enrolDevice = func(_ *identity.Client, _ context.Context, token string, _ time.Duration, _ identity.RetryNotice) (*identity.Material, error) {
		return nil, errors.New("refused " + token)
	}
	if err := runConnect("test", append([]string{hangupSentinelToken, "--logins", "root"}, connectArgs[1:]...)); err == nil {
		t.Fatal("connect succeeded, want the enrolment failure")
	}
	if len(*lines) != 1 || (*lines)[0] != "localport connect: failed" {
		t.Fatalf("system log %q, want only %q", *lines, "localport connect: failed")
	}
}

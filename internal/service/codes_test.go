package service

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/localport/agent/internal/errcode"
)

func wantCode(t *testing.T, err error, code errcode.Code) {
	t.Helper()
	if !errors.Is(err, errcode.New(code)) {
		t.Fatalf("err = %v, want code %s", err, code)
	}
}

// A failed service manager command is AG135 and still a CommandError; the
// account tools' runner leaves the code to the account step (AG138).
func TestFailedCommandIsCoded(t *testing.T) {
	// A command that exits 1 on each platform.
	fail := []string{"false"}
	if runtime.GOOS == "windows" {
		fail = []string{"cmd", "/c", "exit 1"}
	}
	_, err := managerRun(context.Background(), fail[0], fail[1:]...)
	wantCode(t, err, errcode.ServiceManagerFailed)
	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) || cmdErr.ExitCode != 1 {
		t.Fatalf("err = %v, want the CommandError with exit code 1", err)
	}
	if _, err := execRun(context.Background(), fail[0], fail[1:]...); errors.Is(err, errcode.New(errcode.ServiceManagerFailed)) {
		t.Fatalf("execRun = %v, want no service manager code", err)
	}
	run := func(context.Context, string, ...string) (string, error) {
		return execRun(context.Background(), fail[0], fail[1:]...)
	}
	_, err = ensureAccount(context.Background(), run, &fakeAccounts{}, "")
	wantCode(t, err, errcode.AccountNotChanged)
	if errors.Is(err, errcode.New(errcode.ServiceManagerFailed)) {
		t.Fatalf("account create = %v, want AG138 only", err)
	}
}

func TestUnwritableDefinitionIsCoded(t *testing.T) {
	err := writeOwned(filepath.Join(t.TempDir(), "missing", "localport-device.service"), []byte("x"))
	wantCode(t, err, errcode.ServiceDefinitionFailed)
}

func TestAccountFailuresAreCoded(t *testing.T) {
	_, err := lookupAccount(&fakeAccounts{})
	wantCode(t, err, errcode.AccountMissing)
	_, err = lookupAccount(&fakeAccounts{err: errors.New("nss down")})
	wantCode(t, err, errcode.AccountNotChanged)
}

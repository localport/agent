package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/localport/agent/internal/errcode"
)

func wantCode(t *testing.T, err error, code errcode.Code) {
	t.Helper()
	if !errors.Is(err, errcode.New(code)) {
		t.Fatalf("err = %v, want code %s", err, code)
	}
}

// A failed service manager command is AG135 and still a CommandError.
func TestFailedCommandIsCoded(t *testing.T) {
	_, err := execRun(context.Background(), "false")
	wantCode(t, err, errcode.ServiceManagerFailed)
	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) || cmdErr.ExitCode != 1 {
		t.Fatalf("err = %v, want the CommandError with exit code 1", err)
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

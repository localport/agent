package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/service"
)

// appCheckingManager is a fakeManager that, like launchd, installs a session
// app from beside the CLI and refuses it with appErr.
type appCheckingManager struct {
	*fakeManager
	appErr  error
	checked []string
}

func (m *appCheckingManager) CheckApp(_ context.Context, exe string) error {
	m.checked = append(m.checked, exe)
	return m.appErr
}

// up refuses a session app Install would refuse before the join token is
// spent or anything is installed. The test runs up only; service install
// runs the same check through prepareService.
func TestSessionAppIsCheckedBeforeTheSpend(t *testing.T) {
	refused := errcode.New(errcode.SessionAppInvalid)
	fake := &fakeManager{}
	asRoot(t, fake)
	m := &appCheckingManager{fakeManager: fake, appErr: refused}
	newServiceManager = func() (service.Manager, error) { return m, nil }
	calls := fakeEnrol(t, gw01)
	if err := runUp("test", upArgs); !errors.Is(err, refused) {
		t.Fatalf("up with a refused app = %v, want AG014", err)
	}
	if *calls != 0 || fake.installs != 0 {
		t.Fatalf("the join token was spent %d times, installs %d", *calls, fake.installs)
	}
	if len(m.checked) != 1 {
		t.Fatalf("CheckApp ran %d times, want once", len(m.checked))
	}
}

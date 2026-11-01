package cli

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/identity"
)

// A device whose credential is missing is skipped; with none left, run
// refuses to start rather than idling.
func TestRunRefusesWhenNoDeviceCanStart(t *testing.T) {
	base := t.TempDir()
	store := &identity.Store{Root: filepath.Join(base, "identity"), Base: base, BaseChosen: true}
	missing := config.LocalDevice{Identity: identity.Ref{Team: "01kpq7x2abcd34", Kind: identity.KindDevice, Identity: "factory.gw-01"}}
	if err := serveDevices(context.Background(), "test", store, []config.LocalDevice{missing}, true, false, nil); !errors.Is(err, errNoDeviceStarts) {
		t.Fatalf("serveDevices = %v, want errNoDeviceStarts", err)
	}
}

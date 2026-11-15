package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/localport/agent/internal/agent"
	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/proto"
	"github.com/localport/agent/internal/recording"
	"github.com/localport/agent/internal/securitytest"
	"github.com/localport/agent/internal/tunnel"
)

func spooledMeta(id, identifier string) recording.Meta {
	return recording.Meta{
		ID:             id,
		SessionID:      "33333333-3333-4333-8333-333333333333",
		Identifier:     identifier,
		LastAcceptedAt: time.Now(),
		WrappedDEK:     bytes.Repeat([]byte{1}, 100),
		KeySHA256:      bytes.Repeat([]byte{0xaa}, 32),
		Policy:         recording.PolicyBestEffort,
	}
}

// A store with an empty Base keeps its spool under Root, the state root the
// credential walk uses, and follows Root when it is a symlink as that walk does.
func TestOpenUploaderSpoolsUnderRootWhenBaseIsEmpty(t *testing.T) {
	real := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, root); err != nil {
		t.Fatal(err)
	}
	store := &identity.Store{Root: root}
	want := filepath.Join(root, "recordings")
	if got := recordingSpoolDir(store); got != want {
		t.Fatalf("recordingSpoolDir = %q, want %q", got, want)
	}
	if u := openUploader(store, func(string) bool { return false }, func(string) (recording.Client, error) { return nil, recording.ErrNoSessionMux }); u == nil {
		t.Fatal("openUploader returned nil")
	}
	requirePrivateSpool(t, filepath.Join(real, "recordings"))
}

// requirePrivateSpool fails unless dir is a directory only its owner can
// reach: mode 0700 on Unix, a DACL granting only this account, SYSTEM and
// Administrators on Windows, where Go derives no mode bits from the DACL.
func requirePrivateSpool(t *testing.T, dir string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		securitytest.RequireOwnerOnly(t, dir)
		return
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Fatalf("spool directory mode %#o, want 0700", perm)
	}
}

// openUploader makes <state root>/recordings private (0700) and resumes the
// entries spooled before it ran: the entry of a configured device waits for
// that device's session mux, the entry of a device no longer configured is
// dropped from the spool without asking for a client.
func TestOpenUploaderResumesTheSpoolOfConfiguredDevices(t *testing.T) {
	base := t.TempDir()
	store := &identity.Store{Root: filepath.Join(base, "identity"), Base: base, BaseChosen: true}
	dir := filepath.Join(base, "recordings")
	const kept, dropped = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	earlier, _, err := recording.OpenSpool(base, dir, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []recording.Meta{spooledMeta(kept, "factory.gw-01"), spooledMeta(dropped, "factory.gw-02")} {
		if err := earlier.CreateEntry(m); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var asked []string
	first := make(chan struct{}, 1)
	u := openUploader(store, func(id string) bool { return id == deviceRef("factory.gw-01").Identity }, func(identifier string) (recording.Client, error) {
		mu.Lock()
		asked = append(asked, identifier)
		mu.Unlock()
		select {
		case first <- struct{}{}:
		default:
		}
		return nil, recording.ErrNoSessionMux
	})
	if u == nil {
		t.Fatal("openUploader returned nil")
	}
	requirePrivateSpool(t, dir)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		u.Run(ctx)
		close(done)
	}()
	select {
	case <-first:
	case <-time.After(10 * time.Second):
		t.Fatal("the resumed entry never asked for a client")
	}
	// Run removes the dropped entry in the dispatch pass that started the
	// kept one, before it waits again, so it is gone once Run returns.
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if slices.Contains(asked, "factory.gw-02") || !slices.Contains(asked, "factory.gw-01") {
		t.Fatalf("clients asked for %q, want factory.gw-01 only", asked)
	}
	entries, err := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if err != nil || !slices.Equal(names, []string{kept}) {
		t.Fatalf("spool after resume = %q, %v, want %q", names, err, []string{kept})
	}
}

// A device with no running tunnel, known or not, has no session mux.
func TestDeviceRecordingClientWithoutARunningTunnel(t *testing.T) {
	a := agent.New(&config.Config{Devices: []config.DeviceSpec{{Name: "gw-01", Identity: "factory.gw-01"}}})
	for _, identifier := range []string{"factory.gw-01", "factory.gw-02"} {
		if c, err := deviceRecordingClient(a, identifier); !errors.Is(err, recording.ErrNoSessionMux) || c != nil {
			t.Fatalf("deviceRecordingClient(%s) = %v, %v, want ErrNoSessionMux", identifier, c, err)
		}
	}
}

// Two fleets may each hold a device with the same prefix; each identity finds
// its own tunnel.
func TestDeviceTunnelMatchesIdentityNotPrefix(t *testing.T) {
	devices := []config.DeviceSpec{
		{Name: "laptop", Identity: "fleet1.laptop"},
		{Name: "laptop", Identity: "fleet2.laptop"},
	}
	tunnels := []*tunnel.Tunnel{tunnel.New(tunnel.Options{Label: "laptop", Kind: proto.KindTunnel})}
	for _, d := range devices {
		tunnels = append(tunnels, tunnel.New(tunnel.Options{Label: d.Name, Identity: d.Identity, Kind: proto.KindDevice}))
	}
	for i, d := range devices {
		if got := deviceTunnel(tunnels, d.Identity); got != tunnels[i+1] {
			t.Fatalf("deviceTunnel(%s) = %p, want %p", d.Identity, got, tunnels[i+1])
		}
	}
	if got := deviceTunnel(tunnels, "fleet3.laptop"); got != nil {
		t.Fatalf("deviceTunnel(fleet3.laptop) = %p, want nil", got)
	}
}

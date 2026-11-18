package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/localport/agent/internal/agent"
	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/launcher"
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

// A reload signal that arrives before the agent runs is applied once it runs,
// never against an agent that refuses changes as not running.
func TestReloadWaitsForTheAgentToRun(t *testing.T) {
	sig := make(chan os.Signal, 1)
	sig <- os.Interrupt
	saved := notifyReload
	notifyReload = func() (<-chan os.Signal, func()) { return sig, func() {} }
	t.Cleanup(func() { notifyReload = saved })

	a := agent.New(&config.Config{Devices: []config.DeviceSpec{{Name: "gw-01", Identity: "tun12345.gw-01", Edge: "127.0.0.1:1", Host: "127.0.0.1"}}})
	running := make(chan bool, 1)
	load := func() ([]config.LocalDevice, error) {
		_, err := a.Apply(nil, nil)
		running <- !errors.Is(err, agent.ErrNotRunning)
		return nil, errors.New("test config")
	}
	ctx, cancel := context.WithCancel(context.Background())
	watched := make(chan struct{})
	go func() {
		(&deviceRunner{logEvent: func(string) {}}).watchReload(ctx, a, load)
		close(watched)
	}()
	// The watcher holds the queued signal; the agent starts later.
	time.Sleep(200 * time.Millisecond)
	ran := make(chan error, 1)
	go func() { ran <- a.Run(ctx, nil) }()
	select {
	case ok := <-running:
		if !ok {
			t.Fatal("the reload ran before the agent did, and was refused")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the queued reload never ran")
	}
	cancel()
	a.Stop()
	<-watched
	<-ran
}

// storeDeviceCredential writes a device credential for ref into store as the
// store lays it out (meta.json, certificate and key files).
func storeDeviceCredential(t *testing.T, store *identity.Store, ref identity.Ref, region string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spiffe, err := url.Parse("spiffe://" + ref.Team + ".mtls.localport.dev/device/" + ref.Identity)
	if err != nil {
		t.Fatal(err)
	}
	notAfter := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0x2a), NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter, URIs: []*url.URL{spiffe},
	}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	meta := identity.Meta{
		Identity: ref.Identity, Team: ref.Team, Kind: ref.Kind, SpiffeID: spiffe.String(),
		Key:  identity.KeyRef{Backing: identity.BackingFile, File: "key-2a.pem"},
		Cert: "cert-2a.pem", Source: identity.SourceToken, APIURL: "https://api.localport.io",
		Serial: "2a", NotAfter: notAfter, UpdatedAt: time.Now().UTC(),
		Device: &identity.DeviceInfo{Host: "gw-01-factory.eu.localport.dev", Region: region},
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	dir := store.Dir(ref)
	for name, body := range map[string][]byte{
		"meta.json":   raw,
		"cert-2a.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"key-2a.pem":  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// deviceSpec carries the stored device's identity, the prefix as its name,
// its region's edge and its config settings into the spec the agent runs.
func TestDeviceSpecCarriesTheStoredDevice(t *testing.T) {
	store := &identity.Store{Root: t.TempDir()}
	ref := identity.Ref{Team: "01kpq7x2abcd34", Kind: identity.KindDevice, Identity: "tun12345.gw-01"}
	storeDeviceCredential(t, store, ref, "eu")
	d := config.LocalDevice{Identity: ref, Host: "10.0.0.5", Enable: []config.Capability{config.CapabilityTerminal}, Logins: []string{"pi"}}
	spec, renews, err := deviceSpec(store, d, sessionProbe{}, func(string) {})
	if err != nil {
		t.Fatalf("deviceSpec = %v", err)
	}
	if spec.Identity != ref.Identity || spec.Name != "gw-01" || spec.Host != "10.0.0.5" || spec.Edge != resolveEdge("eu") {
		t.Fatalf("spec identity=%q name=%q host=%q edge=%q", spec.Identity, spec.Name, spec.Host, spec.Edge)
	}
	if len(spec.Capabilities) != 1 || spec.Capabilities[0] != "terminal" || len(spec.Logins) != 1 || spec.Logins[0] != "pi" {
		t.Fatalf("spec capabilities=%v logins=%v", spec.Capabilities, spec.Logins)
	}
	if spec.Credential == nil || !renews {
		t.Fatalf("credential=%v renews=%v, want a registrar over a renewable credential", spec.Credential, renews)
	}
}

// A foreground `run --system` without root (an elevated Administrator) is
// refused before it serves anything: up, down and set could not reach it.
func TestSystemRunNeedsPrivilege(t *testing.T) {
	asRoot(t, &fakeManager{})
	privilegedProcess = func() bool { return false }
	prev := listenControl
	t.Cleanup(func() { listenControl = prev })
	listenControl = func() (*launcher.ControlListener, error) {
		return nil, errors.New("the test reached the control endpoint")
	}
	if err := runRun("test", []string{"--system"}); !errors.Is(err, errcode.New(errcode.SystemRunNotPrivileged)) {
		t.Fatalf("unprivileged run --system = %v, want AG159", err)
	}
}

// Root opens the control endpoint only for a run that gets past its flags to
// serve in the foreground: a help request or a flag error ends it first,
// --service runs as the device service, and a flag value is never taken for a
// flag.
func TestRunServesInForeground(t *testing.T) {
	for _, c := range []struct {
		args []string
		want bool
	}{
		{[]string{"--system"}, true},
		{[]string{"--log-file", "-h"}, true},
		{[]string{"--help"}, false},
		{[]string{"-h"}, false},
		{[]string{"--nope"}, false},
		{[]string{"extra"}, false},
		{[]string{"--service"}, false},
		{[]string{"--system", "--service"}, false},
	} {
		if got := runServesInForeground(c.args); got != c.want {
			t.Errorf("runServesInForeground(%q) = %v, want %v", c.args, got, c.want)
		}
	}
}

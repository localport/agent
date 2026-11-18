package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/localport/agent/internal/agent"
	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/session"
	"github.com/localport/agent/internal/tunnel"
)

// endHarness serves one stored device as the service does (reload set), its
// edge a closed address so the tunnel keeps retrying, and hands the test the
// runner and agent.
type endHarness struct {
	store  *identity.Store
	ref    identity.Ref
	runner *deviceRunner
	agent  *agent.Agent
	cancel context.CancelFunc
	done   chan error
}

func serveOneDevice(t *testing.T, d config.LocalDevice, storeIt bool) *endHarness {
	t.Helper()
	edge := closedAddr(t)
	prev := resolveEdge
	resolveEdge = func(string) string { return edge }
	t.Cleanup(func() { resolveEdge = prev })

	base := t.TempDir()
	h := &endHarness{store: &identity.Store{Root: filepath.Join(base, "identity"), Base: base, BaseChosen: true}, ref: d.Identity, done: make(chan error, 1)}
	if storeIt {
		storeDevice(t, h.store, h.ref, "http://"+closedAddr(t))
	}
	serving := make(chan struct{})
	runnerServing = func(r *deviceRunner, a *agent.Agent) {
		h.runner, h.agent = r, a
		close(serving)
	}
	t.Cleanup(func() { runnerServing = nil })

	var ctx context.Context
	ctx, h.cancel = context.WithCancel(context.Background())
	reload := func() ([]config.LocalDevice, error) { return []config.LocalDevice{d}, nil }
	go func() { h.done <- serveDevices(ctx, "test", h.store, []config.LocalDevice{d}, true, false, reload) }()
	select {
	case <-serving:
	case err := <-h.done:
		t.Fatalf("serveDevices returned %v before serving", err)
	case <-time.After(15 * time.Second):
		t.Fatal("serveDevices did not serve within 15 s")
	}
	t.Cleanup(func() {
		h.cancel()
		select {
		case <-h.done:
		case <-time.After(15 * time.Second):
			t.Error("serveDevices did not return within 15 s of its parent ending")
		}
	})
	return h
}

// tunnel is the device's running tunnel, waited for.
func (h *endHarness) tunnel(t *testing.T) *tunnel.Tunnel {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if tn := deviceTunnel(h.agent.Tunnels(), h.ref.Identity); tn != nil {
			return tn
		}
		if time.Now().After(deadline) {
			t.Fatal("the device tunnel did not start")
		}
	}
}

// alive fails the test when serveDevices has returned.
func (h *endHarness) alive(t *testing.T) {
	t.Helper()
	select {
	case err := <-h.done:
		t.Fatalf("serveDevices returned %v; the service must keep running", err)
	case <-time.After(100 * time.Millisecond):
	}
}

func testDeviceRef() identity.Ref {
	return identity.Ref{Team: "01kpq7x2abcd34", Kind: identity.KindDevice, Identity: "tun12345.gw-01"}
}

// The service keeps running with no device that can start and waits for a
// reload. A foreground run refuses (TestRunRefusesWhenNoDeviceCanStart).
func TestServiceIdlesWithNoDeviceThatCanStart(t *testing.T) {
	h := serveOneDevice(t, config.LocalDevice{Identity: testDeviceRef()}, false)
	h.alive(t)
	if n := len(h.agent.Tunnels()); n != 0 {
		t.Fatalf("%d tunnels run with no credential", n)
	}
}

// A removal refusal (SE018) of the device's last tunnel forgets its
// credential and leaves a tombstone; the service keeps running. Its tunnel is
// stopped and its sessions lock released before the credential is deleted.
func TestRemovedDeviceIsForgottenAndTheServiceKeepsRunning(t *testing.T) {
	d := config.LocalDevice{Identity: testDeviceRef(), Enable: []config.Capability{config.CapabilityDesktop}, RDP: "127.0.0.1:3389"}
	h := serveOneDevice(t, d, true)
	tn := h.tunnel(t)

	order := make(chan error, 1)
	h.runner.forget = func(ctx context.Context, ref identity.Ref, code, serial string) (bool, error) {
		var err error
		switch {
		case deviceTunnel(h.agent.Tunnels(), ref.Identity) != nil:
			err = errors.New("the tunnel still runs")
		default:
			// The sessions lock is free only once the device ended.
			lockDir, lockErr := h.store.LockDir(ref)
			var lock *session.SessionsLock
			if lockErr == nil {
				lock, lockErr = session.LockSessions(lockDir)
			}
			if lockErr != nil {
				err = lockErr
			} else {
				_ = lock.Close()
			}
		}
		// Reported once Forget returns, so the test checks a finished
		// removal.
		forgot, forgetErr := h.store.Forget(ctx, ref, code, serial)
		order <- err
		return forgot, forgetErr
	}
	h.runner.queueEnd(deviceEnd{identifier: h.ref.Identity, tunnel: tn,
		err: &tunnel.RegistrationError{Code: identity.CodeDeviceUnknown, Serial: "07"}})
	select {
	case err := <-order:
		if err != nil {
			t.Fatalf("forget ran before the device ended: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the removal was not handled")
	}
	h.alive(t)
	if _, err := os.Stat(h.store.Dir(h.ref)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("credential directory after removal: %v, want deleted", err)
	}
	if ts, err := h.store.ReadTombstone(h.ref); err != nil || ts == nil || ts.Code != identity.CodeDeviceUnknown {
		t.Fatalf("tombstone = %+v, %v; want SE018", ts, err)
	}
}

// A removal refusal of a certificate other than the stored one (a re-enrolment
// replaced it) deletes nothing.
func TestRemovalOfAReplacedCertificateKeepsTheCredential(t *testing.T) {
	h := serveOneDevice(t, config.LocalDevice{Identity: testDeviceRef()}, true)
	tn := h.tunnel(t)
	h.runner.queueEnd(deviceEnd{identifier: h.ref.Identity, tunnel: tn,
		err: &tunnel.RegistrationError{Code: identity.CodeDeviceCertRevoked, Serial: "ff"}})
	// The device runs again with the stored credential.
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if next := deviceTunnel(h.agent.Tunnels(), h.ref.Identity); next != nil && next != tn {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the device did not restart with its stored credential")
		}
	}
	if _, err := h.store.Load(h.ref); err != nil {
		t.Fatalf("credential after a stale removal: %v", err)
	}
}

// A removal the renewer or key refresher reports (no tunnel in the end) also
// stops the device's tunnel and forgets its credential.
func TestRemovalFromRenewalForgetsTheDevice(t *testing.T) {
	d := config.LocalDevice{Identity: testDeviceRef()}
	h := serveOneDevice(t, d, true)
	h.tunnel(t)
	cur, err := h.store.Load(h.ref)
	if err != nil {
		t.Fatal(err)
	}
	h.runner.queueEnd(deviceEnd{identifier: h.ref.Identity,
		err: &identity.RemovedError{Code: identity.CodeDeviceCertRevoked, Serial: cur.Meta.Serial, Err: errors.New("revoked")}})
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(h.store.Dir(h.ref)); errors.Is(err, os.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the credential was not forgotten")
		}
	}
	if deviceTunnel(h.agent.Tunnels(), h.ref.Identity) != nil {
		t.Fatal("the removed device's tunnel still runs")
	}
	h.alive(t)
}

// Any other refusal for good (SE031 not pending) parks the device: its tunnel
// stops and nothing is deleted.
func TestRefusedDeviceIsParkedNotForgotten(t *testing.T) {
	h := serveOneDevice(t, config.LocalDevice{Identity: testDeviceRef()}, true)
	tn := h.tunnel(t)
	h.runner.queueEnd(deviceEnd{identifier: h.ref.Identity, tunnel: tn,
		err: &tunnel.RegistrationError{Code: "SE031", Serial: "07"}})
	for deadline := time.Now().Add(10 * time.Second); deviceTunnel(h.agent.Tunnels(), h.ref.Identity) != nil; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the parked device's tunnel still runs")
		}
	}
	h.alive(t)
	if _, err := h.store.Load(h.ref); err != nil {
		t.Fatalf("credential after parking: %v, want kept", err)
	}
	if ts, _ := h.store.ReadTombstone(h.ref); ts != nil {
		t.Fatal("a parked device got a tombstone")
	}
}

// A device parked by a refusal that carried no code is retried at reload, as
// any parked device is.
func TestCodelessParkedDeviceIsRetriedAtReload(t *testing.T) {
	sig := make(chan os.Signal, 1)
	prev := notifyReload
	notifyReload = func() (<-chan os.Signal, func()) { return sig, func() {} }
	t.Cleanup(func() { notifyReload = prev })
	h := serveOneDevice(t, config.LocalDevice{Identity: testDeviceRef()}, true)
	tn := h.tunnel(t)
	h.runner.queueEnd(deviceEnd{identifier: h.ref.Identity, tunnel: tn, err: errors.New("refused without a code")})
	for deadline := time.Now().Add(10 * time.Second); deviceTunnel(h.agent.Tunnels(), h.ref.Identity) != nil; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the parked device's tunnel still runs")
		}
	}
	sig <- os.Interrupt // any value: the channel is the reload signal
	if again := h.tunnel(t); again == tn {
		t.Fatal("reload kept the ended tunnel")
	}
	h.alive(t)
}

// A device with a tombstone and no credential is skipped without a dial.
func TestTombstonedDeviceIsSkipped(t *testing.T) {
	base := t.TempDir()
	store := &identity.Store{Root: filepath.Join(base, "identity"), Base: base, BaseChosen: true}
	ref := testDeviceRef()
	storeDevice(t, store, ref, "http://"+closedAddr(t))
	if ok, err := store.Forget(context.Background(), ref, identity.CodeDeviceUnknown, "07"); !ok || err != nil {
		t.Fatalf("Forget = %v, %v", ok, err)
	}
	if err := serveDevices(context.Background(), "test", store, []config.LocalDevice{{Identity: ref}}, true, false, nil); !errors.Is(err, errNoDeviceStarts) {
		t.Fatalf("serveDevices = %v, want errNoDeviceStarts for a removed device", err)
	}
}

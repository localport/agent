package identity

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/localport/agent/internal/securitytest"
)

func fileExists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

// The control plane promotes the pending certificate when the edge
// authenticates it, and the edge's RegisterClient then fails. The device must
// reconnect with the pending certificate, since the old one is superseded, and
// promote it locally only after the RegisterAck. A fresh registrar, as after a
// restart with pending.json present, also presents the pending certificate.
func TestPromotionFollowedByAFailedRegisterClientStillReconnects(t *testing.T) {
	store, old, next := renewedDevice(t)
	reg := NewDeviceRegistrar(store, deviceRef, nil)

	first, err := reg.Present()
	if err != nil {
		t.Fatal(err)
	}
	if !first.Pending || first.Serial != next.Meta.Serial {
		t.Fatalf("first registration presents %s (pending %v), want the pending %s", first.Serial, first.Pending, next.Meta.Serial)
	}
	// RegisterClient failed: a retryable refusal, no RegisterAck, no Promote.
	retry, err := reg.Present()
	if err != nil {
		t.Fatal(err)
	}
	if retry.Serial != next.Meta.Serial {
		t.Fatalf("the reconnect presents %s, want the pending %s", retry.Serial, next.Meta.Serial)
	}
	if restarted, err := NewDeviceRegistrar(store, deviceRef, nil).Present(); err != nil || restarted.Serial != next.Meta.Serial {
		t.Fatalf("after a restart: %v, %v; want the pending certificate", restarted, err)
	}
	oldKey := filepath.Join(store.Dir(deviceRef), old.Meta.Key.File)
	if !fileExists(t, oldKey) {
		t.Fatal("the old key was deleted before a RegisterAck on the new one")
	}

	reg.Registered(retry)
	cur, err := store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	if cur.Meta.Serial != next.Meta.Serial {
		t.Fatalf("current = %s after the RegisterAck, want %s", cur.Meta.Serial, next.Meta.Serial)
	}
	if fileExists(t, oldKey) {
		t.Fatal("the old key survived the promotion")
	}
	after, err := reg.Present()
	if err != nil || after.Pending || after.Serial != next.Meta.Serial {
		t.Fatalf("after promotion: %+v, %v; want the promoted certificate as current", after, err)
	}
	if after.SessionCache != retry.SessionCache {
		t.Fatal("the same certificate must keep its TLS session cache")
	}
}

// Once the pending certificate was presented, the previous one is never
// presented again, even when the pending one disappears from the store.
func TestNoRegistrationWithTheOldCertificateAfterAPendingAttempt(t *testing.T) {
	store, old, _ := renewedDevice(t)
	reg := NewDeviceRegistrar(store, deviceRef, nil)
	if p, err := reg.Present(); err != nil || !p.Pending {
		t.Fatalf("Present = %+v, %v; want the pending certificate", p, err)
	}
	if err := os.Remove(filepath.Join(store.Dir(deviceRef), pendingFile)); err != nil {
		t.Fatal(err)
	}
	p, err := reg.Present()
	if !errors.Is(err, ErrPendingLost) {
		t.Fatalf("Present = %+v, %v; want ErrPendingLost rather than the old certificate %s", p, err, old.Meta.Serial)
	}
}

// A re-enrolment by another process after a pending attempt replaces the
// credential the attempt was renewed from; the new certificate is presented.
func TestReEnrolmentAfterAPendingAttemptIsPresented(t *testing.T) {
	ca := newTestCA(t)
	store, oldKey := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	srv, _ := renewServer(t, ca, oldKey)
	cur, err := store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&Renewer{Store: store, Ref: deviceRef}).renewLocked(context.Background(), &Client{BaseURL: srv.URL, HTTP: srv.Client()}, cur); err != nil {
		t.Fatal(err)
	}
	reenrolled := 0
	reg := NewDeviceRegistrar(store, deviceRef, func(event string) {
		if strings.Contains(event, "was enrolled again") {
			reenrolled++
		}
	})
	if p, err := reg.Present(); err != nil || !p.Pending {
		t.Fatalf("Present = %+v, %v; want the pending certificate", p, err)
	}

	key := testKey(t)
	if _, err := store.Save(context.Background(), Material{
		CertPEM: ca.sign(t, &key.PublicKey, time.Now().Add(-time.Minute), time.Now().Add(30*24*time.Hour)),
		Key:     fileKey{key},
		Meta:    Meta{APIURL: "https://api.localport.io", Source: SourceToken, Device: &DeviceInfo{Host: "gw-01.factory.eu.localport.dev", Region: "eu"}},
	}); err != nil {
		t.Fatal(err)
	}
	enrolled, err := store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	// The re-enrolment starts the attempt tracking over, so the next
	// registration is an ordinary one.
	for range 2 {
		p, err := reg.Present()
		if err != nil || p.Pending || p.Serial != enrolled.Meta.Serial {
			t.Fatalf("Present = %+v, %v; want the re-enrolled certificate %s", p, err, enrolled.Meta.Serial)
		}
	}
	if reenrolled != 1 {
		t.Fatalf("re-enrolment reported %d times over two registrations, want 1", reenrolled)
	}
}

// Each presented certificate has its own TLS session cache, so the handshake
// after the switch cannot resume a session bound to the old certificate.
func TestASwitchedCertificateGetsAFreshSessionCache(t *testing.T) {
	ca := newTestCA(t)
	store, oldKey := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	reg := NewDeviceRegistrar(store, deviceRef, nil)
	before, err := reg.Present()
	if err != nil || before.Pending {
		t.Fatalf("Present = %+v, %v", before, err)
	}
	srv, _ := renewServer(t, ca, oldKey)
	cur, _ := store.Load(deviceRef)
	if _, err := (&Renewer{Store: store, Ref: deviceRef}).renewLocked(context.Background(), &Client{BaseURL: srv.URL, HTTP: srv.Client()}, cur); err != nil {
		t.Fatal(err)
	}
	after, err := reg.Present()
	if err != nil || !after.Pending {
		t.Fatalf("Present = %+v, %v", after, err)
	}
	if after.SessionCache == before.SessionCache {
		t.Fatal("the pending certificate reuses the old certificate's session cache")
	}
}

// A promotion the renewal lock blocks is retried by Tick, not dropped.
func TestPromotionBlockedByARenewalIsRetried(t *testing.T) {
	store, _, next := renewedDevice(t)
	reg := NewDeviceRegistrar(store, deviceRef, nil)
	p, err := reg.Present()
	if err != nil {
		t.Fatal(err)
	}
	release, held, err := store.tryLock(deviceRef)
	if err != nil || !held {
		t.Fatalf("lock: held=%v err=%v", held, err)
	}
	reg.Registered(p)
	release()
	if cur, _ := store.Load(deviceRef); cur.Meta.Serial == next.Meta.Serial {
		t.Fatal("promoted while the lock was held")
	}
	reg.Tick(p, time.Now())
	if cur, _ := store.Load(deviceRef); cur.Meta.Serial != next.Meta.Serial {
		t.Fatalf("current = %s after Tick, want %s", cur.Meta.Serial, next.Meta.Serial)
	}
}

// A session registered with the current certificate is due to switch once a
// renewal is pending, and forced to within RolloverDeadline of expiry.
func TestTickReportsARolloverAndItsDeadline(t *testing.T) {
	ca := newTestCA(t)
	notAfter := time.Now().Add(30 * 24 * time.Hour)
	store, oldKey := savedDevice(t, ca, time.Now().Add(-time.Hour), notAfter)
	reg := NewDeviceRegistrar(store, deviceRef, nil)
	p, err := reg.Present()
	if err != nil {
		t.Fatal(err)
	}
	if due, _ := reg.Tick(p, time.Now()); due {
		t.Fatal("due with nothing pending")
	}
	srv, _ := renewServer(t, ca, oldKey)
	cur, _ := store.Load(deviceRef)
	if _, err := (&Renewer{Store: store, Ref: deviceRef}).renewLocked(context.Background(), &Client{BaseURL: srv.URL, HTTP: srv.Client()}, cur); err != nil {
		t.Fatal(err)
	}
	if due, force := reg.Tick(p, time.Now()); !due || force {
		t.Fatalf("Tick = due %v force %v, want due and not forced", due, force)
	}
	if due, force := reg.Tick(p, cur.Meta.NotAfter.Add(-time.Hour)); !due || !force {
		t.Fatalf("Tick near expiry = due %v force %v, want forced", due, force)
	}
	pending, err := reg.Present()
	if err != nil || !pending.Pending {
		t.Fatal("the next registration must present the pending certificate")
	}
	if due, _ := reg.Tick(pending, time.Now()); due {
		t.Fatal("a session on the pending certificate is not due to switch")
	}
}

// A store read error is returned for a retry and deletes nothing.
func TestAStoreReadErrorIsRetriedAndKeepsTheCredential(t *testing.T) {
	store, old, next := renewedDevice(t)
	dir := store.Dir(deviceRef)
	restore := untrustDir(t, dir)
	reg := NewDeviceRegistrar(store, deviceRef, nil)
	if _, err := reg.Present(); err == nil {
		t.Fatal("Present succeeded on an untrusted credential directory")
	}
	restore()
	for _, f := range []string{old.Meta.Key.File, next.Meta.Key.File, metaFile, pendingFile} {
		if !fileExists(t, filepath.Join(dir, f)) {
			t.Fatalf("%s was deleted after a read error", f)
		}
	}
	if p, err := reg.Present(); err != nil || p.Serial != next.Meta.Serial {
		t.Fatalf("Present = %+v, %v after the directory was fixed", p, err)
	}
}

// SE031 on the pending certificate renews again from the pending key and
// retries; a definitive renewal refusal stops. SE006 retries; other codes keep
// the edge's verdict.
func TestRefusalOfThePendingCertificateRenewsFromItsKey(t *testing.T) {
	ca := newTestCA(t)
	store, oldKey := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	srv, paths := renewServer(t, ca, oldKey)
	cur, _ := store.Load(deviceRef)
	first, err := (&Renewer{Store: store, Ref: deviceRef}).renewLocked(context.Background(), &Client{BaseURL: srv.URL, HTTP: srv.Client()}, cur)
	if err != nil {
		t.Fatal(err)
	}

	// The second renewal must be signed by the pending key.
	pendingKey := first.Key.(fileKey).PrivateKey
	srv2, _ := renewServer(t, ca, pendingKey)
	reg := NewDeviceRegistrar(store, deviceRef, nil)
	reg.client = &Client{BaseURL: srv2.URL, HTTP: srv2.Client()}
	p, err := reg.Present()
	if err != nil || !p.Pending {
		t.Fatalf("Present = %+v, %v", p, err)
	}
	if retry, err := reg.Refused(context.Background(), p, codeDeviceCertRefused); !retry || err != nil {
		t.Fatalf("Refused(SE031) = %v, %v; want a retry", retry, err)
	}
	again, err := reg.Present()
	if err != nil || !again.Pending || again.Serial == first.Meta.Serial {
		t.Fatalf("Present after the renewal = %+v, %v; want a new pending certificate", again, err)
	}
	if len(*paths) != 1 {
		t.Fatalf("renewals from the current key = %d, want 1", len(*paths))
	}

	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(refusing.Close)
	reg.client = &Client{BaseURL: refusing.URL, HTTP: refusing.Client()}
	if retry, err := reg.Refused(context.Background(), again, codeDeviceCertRefused); retry || err == nil {
		t.Fatalf("Refused(SE031) with the renewal refused = %v, %v; want stop", retry, err)
	}
	if retry, _ := reg.Refused(context.Background(), again, codeCertExpired); !retry {
		t.Fatal("SE006 must be retried")
	}
	current := &Presentation{Serial: cur.Meta.Serial}
	if retry, _ := reg.Refused(context.Background(), current, codeDeviceCertRefused); retry {
		t.Fatal("SE031 on the current certificate must stop")
	}
}

// A save after a spent one-time secret lands even when ctx is cancelled while
// a renewal holds the lock.
func TestSaveIssuedLandsAfterTheContextEnds(t *testing.T) {
	ca := newTestCA(t)
	store, _ := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	release, held, err := store.tryLock(deviceRef)
	if err != nil || !held {
		t.Fatalf("lock: held=%v err=%v", held, err)
	}
	key := testKey(t)
	m := Material{
		CertPEM: ca.sign(t, &key.PublicKey, time.Now().Add(-time.Minute), time.Now().Add(time.Hour)),
		Key:     fileKey{key},
		Meta:    Meta{APIURL: "https://api.localport.io", Source: SourceToken},
	}
	ctx, cancel := context.WithCancel(context.Background())
	saved := make(chan error, 1)
	go func() {
		_, err := store.SaveIssued(ctx, m)
		saved <- err
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	time.Sleep(2 * lockPollInterval)
	release()
	select {
	case err := <-saved:
		if err != nil {
			t.Fatalf("SaveIssued = %v, want the save to land", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SaveIssued did not finish after the lock freed")
	}
	got, err := store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := leafOf(m.CertPEM)
	if got.Meta.Serial != leaf.SerialNumber.Text(16) {
		t.Fatal("the issued credential was not saved")
	}
}

// A session that registered with a pending certificate keeps that
// presentation after the promotion; the next renewal must still roll it over.
func TestTwoConsecutiveRollovers(t *testing.T) {
	ca := newTestCA(t)
	store, key0 := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	reg := NewDeviceRegistrar(store, deviceRef, nil)
	renew := func(key any) {
		t.Helper()
		srv, _ := renewServer(t, ca, key.(*ecdsa.PrivateKey))
		cur, err := store.Load(deviceRef)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := (&Renewer{Store: store, Ref: deviceRef}).renewLocked(context.Background(), &Client{BaseURL: srv.URL, HTTP: srv.Client()}, cur); err != nil {
			t.Fatal(err)
		}
	}

	p0, err := reg.Present()
	if err != nil {
		t.Fatal(err)
	}
	renew(key0)
	if due, _ := reg.Tick(p0, time.Now()); !due {
		t.Fatal("first rollover not due")
	}
	p1, err := reg.Present()
	if err != nil || !p1.Pending {
		t.Fatalf("Present = %+v, %v", p1, err)
	}
	reg.Registered(p1)
	if due, _ := reg.Tick(p1, time.Now()); due {
		t.Fatal("due right after the promotion, with nothing pending")
	}
	cur, err := store.Load(deviceRef)
	if err != nil || cur.Meta.Serial != p1.Serial {
		t.Fatalf("current = %v, %v; want the promoted %s", cur, err, p1.Serial)
	}
	renew(cur.Key.(fileKey).PrivateKey)
	if due, _ := reg.Tick(p1, time.Now()); !due {
		t.Fatal("second rollover not due: the session registered with a since-promoted pending certificate")
	}
	if due, force := reg.Tick(p1, cur.Meta.NotAfter.Add(-time.Hour)); !due || !force {
		t.Fatalf("second rollover near expiry = due %v force %v, want forced", due, force)
	}
}

// SE006 stops being retried while the renewal loop reports a definitive
// refusal, and is retried again once a renewal lands.
func TestExpiredRefusalStopsAfterADefinitiveRenewalRefusal(t *testing.T) {
	store, _, _ := renewedDevice(t)
	reg := NewDeviceRegistrar(store, deviceRef, nil)
	p, err := reg.Present()
	if err != nil {
		t.Fatal(err)
	}
	refusal := errors.New("renewal refused")
	reg.RenewalRefused(refusal)
	if retry, err := reg.Refused(context.Background(), p, codeCertExpired); retry || !errors.Is(err, refusal) {
		t.Fatalf("Refused(SE006) after a refusal = %v, %v; want stop with the refusal", retry, err)
	}
	reg.RenewalRefused(nil)
	if retry, _ := reg.Refused(context.Background(), p, codeCertExpired); !retry {
		t.Fatal("SE006 not retried after the refusal cleared")
	}
}

// A device credential cannot be opened as a consumer credential.
func TestOpenRefRefusesADeviceCredential(t *testing.T) {
	store, _, _ := renewedDevice(t)
	if _, err := OpenRef(store, deviceRef); !errors.Is(err, ErrDeviceCredential) {
		t.Fatalf("OpenRef(device) = %v, want ErrDeviceCredential", err)
	}
}

// The system store sits beside the config directory and never follows it;
// the identity directory is its own walk base on every OS.
func TestSystemStoreRootsBesideTheConfigDirectory(t *testing.T) {
	t.Setenv(HomeEnv, t.TempDir())
	dir := filepath.Join(t.TempDir(), "Localport")
	s, err := SystemStore(dir)
	if err != nil || s.Root != filepath.Join(dir, "identity") || s.Base != s.Root || s.BaseChosen {
		t.Fatalf("SystemStore = %+v, %v", s, err)
	}
	if err := s.EnsureRoot(); err != nil {
		t.Fatal(err)
	}
	// Go derives no mode bits from a DACL: on Windows the DACL is read
	// instead.
	if runtime.GOOS == "windows" {
		securitytest.RequireOwnerOnly(t, s.Root)
	} else if info, err := os.Stat(s.Root); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("store root = %v, %v; want a 0700 directory", info, err)
	}
	if _, err := SystemStore("relative"); err == nil {
		t.Fatal("a relative system directory accepted")
	}
}

// RegisteredCertificate is false before any RegisterAck, returns the current
// certificate after one on it, and the renewed one after a RegisterAck on the
// pending certificate, even while the renewal lock blocks its promotion.
func TestRegisteredCertificateFollowsEveryAcknowledgement(t *testing.T) {
	ca := newTestCA(t)
	store, oldKey := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	reg := NewDeviceRegistrar(store, deviceRef, nil)
	if c, ok := reg.RegisteredCertificate(); ok || c != nil {
		t.Fatalf("RegisteredCertificate before any RegisterAck = %v, %v; want nil, false", c, ok)
	}
	current, err := reg.Present()
	if err != nil || current.Pending {
		t.Fatalf("Present = %+v, %v", current, err)
	}
	reg.Registered(current)
	if c, ok := reg.RegisteredCertificate(); !ok || c != current.Certificate {
		t.Fatalf("after the first RegisterAck = %v, %v; want the current certificate", c, ok)
	}

	srv, _ := renewServer(t, ca, oldKey)
	cur, _ := store.Load(deviceRef)
	if _, err := (&Renewer{Store: store, Ref: deviceRef}).renewLocked(context.Background(), &Client{BaseURL: srv.URL, HTTP: srv.Client()}, cur); err != nil {
		t.Fatal(err)
	}
	pending, err := reg.Present()
	if err != nil || !pending.Pending {
		t.Fatalf("Present = %+v, %v; want the pending certificate", pending, err)
	}
	release, held, err := store.tryLock(deviceRef)
	if err != nil || !held {
		t.Fatalf("lock: held=%v err=%v", held, err)
	}
	defer release()
	reg.Registered(pending)
	if loaded, _ := store.Load(deviceRef); loaded.Meta.Serial == pending.Serial {
		t.Fatal("promoted while the renewal lock was held")
	}
	if c, ok := reg.RegisteredCertificate(); !ok || c != pending.Certificate {
		t.Fatalf("after the pending RegisterAck = %v, %v; want the renewed certificate", c, ok)
	}
}

// A promotion that lands between the store reads of Present never reads as a
// lost pending certificate: Present returns the promoted one.
func TestPresentDuringAPromotionReturnsThePromotedCertificate(t *testing.T) {
	store, _, next := renewedDevice(t)
	reg := NewDeviceRegistrar(store, deviceRef, nil)
	if p, err := reg.Present(); err != nil || !p.Pending {
		t.Fatalf("Present = %+v, %v; want the pending certificate", p, err)
	}
	promoted := false
	store.afterMetaRead = func() {
		if promoted {
			return
		}
		promoted = true
		if err := store.Promote(deviceRef, next.Meta.Serial); err != nil {
			t.Errorf("Promote: %v", err)
		}
	}
	p, err := reg.Present()
	if err != nil {
		t.Fatalf("Present during a promotion: %v", err)
	}
	if !promoted || p.Serial != next.Meta.Serial {
		t.Fatalf("Present = %s (promoted %v), want the promoted %s", p.Serial, promoted, next.Meta.Serial)
	}
}

// A renewal still running under its idempotency key, or rate limited, may
// yet succeed, so neither stops re-registration; other 4xx answers do.
func TestDefinitiveRefusal(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"in flight", &APIError{Status: http.StatusConflict, Code: codeIdempotencyInFlight}, false},
		{"rate limited", &APIError{Status: http.StatusTooManyRequests}, false},
		{"server error", &APIError{Status: http.StatusBadGateway}, false},
		{"forbidden", &APIError{Status: http.StatusForbidden}, true},
		{"other conflict", &APIError{Status: http.StatusConflict, Code: "SE038"}, true},
		{"not renewable", ErrNotRenewable, true},
	} {
		if got := definitiveRefusal(tc.err); got != tc.want {
			t.Errorf("%s: definitiveRefusal = %v, want %v", tc.name, got, tc.want)
		}
	}
}

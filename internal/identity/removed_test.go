package identity

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// refuseWith answers every request with status and the control plane error
// envelope carrying code.
func refuseWith(t *testing.T, status int, code string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		writeJSON(t, w, map[string]any{"code": code, "error": "refused", "message": "refused"})
	}
}

// A renewal refused with SE018 or SE041 reports the refused serial to OnRemoved and
// ends the loop instead of retrying.
func TestRenewerReportsARemovalRefusalAndEnds(t *testing.T) {
	for _, code := range []string{CodeDeviceUnknown, CodeDeviceCertRevoked} {
		t.Run(code, func(t *testing.T) {
			store, _ := savedDevice(t, newTestCA(t), time.Now().Add(-40*24*time.Hour), time.Now().Add(-time.Hour))
			cur, err := store.Load(deviceRef)
			if err != nil {
				t.Fatal(err)
			}
			srv := newServer(t, refuseWith(t, http.StatusNotFound, code))
			removed := make(chan *RemovedError, 1)
			r := &Renewer{
				Store: store, Ref: deviceRef,
				OnEvent:   func(l string) { t.Log(l) },
				OnRemoved: func(e *RemovedError) { removed <- e },
				client:    &Client{BaseURL: srv.URL, HTTP: srv.Client()},
			}
			done := make(chan struct{})
			go func() { defer close(done); r.Run(context.Background()) }()
			got := within(t, removed)
			if got.Code != code || got.Serial != cur.Meta.Serial {
				t.Fatalf("OnRemoved(%s, %s), want (%s, %s)", got.Code, got.Serial, code, cur.Meta.Serial)
			}
			within(t, done)
		})
	}
}

// SE040 is not a removal: the renewal keeps retrying and OnRemoved is not
// called.
func TestRenewerDoesNotReportADisabledDeviceAsRemoved(t *testing.T) {
	store, _ := savedDevice(t, newTestCA(t), time.Now().Add(-40*24*time.Hour), time.Now().Add(-time.Hour))
	srv := newServer(t, refuseWith(t, http.StatusForbidden, CodeDeviceDisabled))
	cur, err := store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	r := &Renewer{Store: store, Ref: deviceRef, client: &Client{BaseURL: srv.URL, HTTP: srv.Client()}}
	_, err = r.renewLocked(context.Background(), r.client, cur)
	var removed *RemovedError
	if err == nil || errors.As(err, &removed) {
		t.Fatalf("renewal refused with SE040 = %v, want an error that is not a RemovedError", err)
	}
}

// A key fetch refused with SE041 reports the refused serial to OnRemoved.
func TestKeyRefresherReportsARemovalRefusal(t *testing.T) {
	f := startKeyRefresher(t, newServer(t, refuseWith(t, http.StatusForbidden, CodeDeviceCertRevoked)), tk1)
	cur, err := f.store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	removed := make(chan *RemovedError, 1)
	f.r.OnRemoved = func(e *RemovedError) { removed <- e }
	f.run(t)
	within(t, f.clock.armed)
	go func() { _ = f.r.RefreshNow(context.Background()) }()
	got := within(t, removed)
	if got.Code != CodeDeviceCertRevoked || got.Serial != cur.Meta.Serial {
		t.Fatalf("OnRemoved(%s, %s), want (%s, %s)", got.Code, got.Serial, CodeDeviceCertRevoked, cur.Meta.Serial)
	}
}

// Forget of the stored serial deletes the credential and leaves a tombstone
// that Tombstones lists; a new enrolment's Save deletes the tombstone.
func TestForgetDeletesTheCredentialAndSaveClearsTheTombstone(t *testing.T) {
	ca := newTestCA(t)
	store, key := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	cur, err := store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := store.Forget(context.Background(), deviceRef, CodeDeviceUnknown, cur.Meta.Serial)
	if err != nil || !ok {
		t.Fatalf("Forget = %v, %v; want true, nil", ok, err)
	}
	if _, err := os.Stat(store.Dir(deviceRef)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("credential directory after Forget: %v, want not exist", err)
	}
	tomb, err := store.ReadTombstone(deviceRef)
	if err != nil || tomb == nil || tomb.Code != CodeDeviceUnknown {
		t.Fatalf("tombstone = %+v, %v; want code %s", tomb, err, CodeDeviceUnknown)
	}
	refs, err := store.Tombstones()
	if err != nil || len(refs) != 1 || refs[0] != deviceRef {
		t.Fatalf("Tombstones = %v, %v; want [%s]", refs, err, deviceRef)
	}

	if _, err := store.Save(context.Background(), Material{
		CertPEM: ca.sign(t, &key.PublicKey, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour)),
		Key:     fileKey{key},
		Meta:    cur.Meta,
	}); err != nil {
		t.Fatal(err)
	}
	if tomb, err := store.ReadTombstone(deviceRef); err != nil || tomb != nil {
		t.Fatalf("tombstone after a new Save = %+v, %v; want none", tomb, err)
	}
}

// A registration presents a pending renewal first: a removal refusal of that
// pending certificate forgets the device, and RenewPending reports a removal
// refusal of it as removed.
func TestForgetMatchesThePendingCertificate(t *testing.T) {
	ca := newTestCA(t)
	store, oldKey := savedDevice(t, ca, time.Now().Add(-40*24*time.Hour), time.Now().Add(-time.Hour))
	srv, _ := renewServer(t, ca, oldKey)
	cur, err := store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	r := &Renewer{Store: store, Ref: deviceRef}
	if _, err := r.renewLocked(context.Background(), &Client{BaseURL: srv.URL, HTTP: srv.Client()}, cur); err != nil {
		t.Fatal(err)
	}
	pending, err := store.LoadPending(deviceRef)
	if err != nil {
		t.Fatal(err)
	}

	refusing := newServer(t, refuseWith(t, http.StatusNotFound, CodeDeviceUnknown))
	_, err = (&Renewer{Store: store, Ref: deviceRef, client: &Client{BaseURL: refusing.URL, HTTP: refusing.Client()}}).RenewPending(context.Background())
	var removed *RemovedError
	if !errors.As(err, &removed) || removed.Serial != pending.Meta.Serial {
		t.Fatalf("RenewPending refused with SE018 = %v, want a RemovedError for the pending serial", err)
	}

	ok, err := store.Forget(context.Background(), deviceRef, CodeDeviceUnknown, pending.Meta.Serial)
	if err != nil || !ok {
		t.Fatalf("Forget of the pending serial = %v, %v; want true, nil", ok, err)
	}
	if _, err := os.Stat(store.Dir(deviceRef)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("credential directory after Forget: %v, want not exist", err)
	}
}

// Forget of a serial a re-enrolment already replaced deletes nothing.
func TestForgetKeepsACredentialWithAnotherSerial(t *testing.T) {
	store, _ := savedDevice(t, newTestCA(t), time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	ok, err := store.Forget(context.Background(), deviceRef, CodeDeviceCertRevoked, "not-the-stored-serial")
	if err != nil || ok {
		t.Fatalf("Forget = %v, %v; want false, nil", ok, err)
	}
	if _, err := store.Load(deviceRef); err != nil {
		t.Fatalf("credential after a mismatched Forget: %v", err)
	}
	if tomb, err := store.ReadTombstone(deviceRef); err != nil || tomb != nil {
		t.Fatalf("tombstone = %+v, %v; want none", tomb, err)
	}
}

// PurgeDevices holds the store lock exclusively: an enrolment that waits on
// it meanwhile finds the credential, its tombstone, the lock directory and the
// store lock deleted before the hold ends, then enrols afresh.
func TestPurgeDevicesWithAnEnrolmentWaiting(t *testing.T) {
	ca := newTestCA(t)
	store, _ := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err := store.writeTombstone(deviceRef, []byte(`{"code":"SE018"}`)); err != nil {
		t.Fatal(err)
	}
	key := testKey(t)
	fresh := Material{
		CertPEM: ca.sign(t, &key.PublicKey, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)),
		Key:     fileKey{key},
		Meta:    Meta{APIURL: "https://api.localport.io", Source: SourceToken, Device: &DeviceInfo{Host: "gw-01.factory.eu.localport.dev", Region: "eu"}},
	}
	waiting := make(chan struct{})
	var once sync.Once
	store.storeShareAttempt = func(held bool) {
		if !held {
			once.Do(func() { close(waiting) })
		}
	}
	store.storeLockReleasing = func() {
		gone := []string{store.Dir(deviceRef), store.tombstonePath(deviceRef), filepath.Join(store.Root, LocksDir)}
		storeLock := filepath.Join(store.Root, storeLockFile)
		if purgeRemovesStoreLock {
			gone = append(gone, storeLock)
		} else if _, err := os.Lstat(storeLock); err != nil {
			t.Errorf("%s before the purge released the store lock: %v, want it kept", storeLock, err)
		}
		for _, p := range gone {
			if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s before the purge released the store lock: %v, want deleted", p, err)
			}
		}
	}
	saved := make(chan error, 1)
	if _, err := store.PurgeDevices(context.Background(), func() error {
		go func() { _, err := store.SaveIssued(context.Background(), fresh); saved <- err }()
		within(t, waiting)
		// The caller's part: the team directory the device leaves empty.
		return os.Remove(filepath.Dir(store.Dir(deviceRef)))
	}); err != nil {
		t.Fatal(err)
	}
	if err := within(t, saved); err != nil {
		t.Fatalf("SaveIssued after the purge: %v", err)
	}
	if _, err := store.Load(deviceRef); err != nil {
		t.Fatalf("Load after the enrolment: %v", err)
	}
}

// A purge of a store whose root does not exist leaves it missing.
func TestPurgeDevicesLeavesAMissingRootMissing(t *testing.T) {
	store := &Store{Root: filepath.Join(t.TempDir(), "identity")}
	if _, err := store.PurgeDevices(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(store.Root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("store root after the purge: %v, want it missing", err)
	}
}

// A re-enrolment that waits on the renewal lock while Forget or Remove holds
// it is never deleted: the delete finishes before the lock is released, then
// the waiting Save creates the directory afresh and commits.
func TestDeleteWithAnEnrolmentWaiting(t *testing.T) {
	forget := func(s *Store, serial string) error {
		ok, err := s.Forget(context.Background(), deviceRef, CodeDeviceCertRevoked, serial)
		if err == nil && !ok {
			err = errors.New("Forget forgot nothing")
		}
		return err
	}
	for _, tc := range []struct {
		name   string
		stored bool
		remove func(*Store, string) error
	}{
		{"Forget", true, forget},
		{"ForgetWithoutACredential", false, forget},
		{"Remove", true, func(s *Store, _ string) error { return s.Remove(context.Background(), deviceRef) }},
	} {
		name, remove := tc.name, tc.remove
		t.Run(name, func(t *testing.T) {
			ca := newTestCA(t)
			store, oldSerial := &Store{Root: t.TempDir()}, "07"
			if tc.stored {
				store, _ = savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
				old, err := store.Load(deviceRef)
				if err != nil {
					t.Fatal(err)
				}
				oldSerial = old.Meta.Serial
			}
			key := testKey(t)
			fresh := Material{
				CertPEM: ca.sign(t, &key.PublicKey, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)),
				Key:     fileKey{key},
				Meta:    Meta{APIURL: "https://api.localport.io", Source: SourceToken, Device: &DeviceInfo{Host: "gw-01.factory.eu.localport.dev", Region: "eu"}},
			}

			var mu sync.Mutex
			deleting, saveWaiting := false, make(chan struct{})
			saved := make(chan error, 1)
			store.renewLockAttempt = func(held bool) {
				mu.Lock()
				first := held && !deleting
				if first {
					deleting = true
				}
				signal := !held && deleting && saveWaiting != nil
				if signal {
					close(saveWaiting)
					saveWaiting = nil
				}
				waiting := saveWaiting
				mu.Unlock()
				if first {
					// The delete holds the lock: start the enrolment and hold
					// the delete until the enrolment waits on the lock.
					go func() { _, err := store.SaveIssued(context.Background(), fresh); saved <- err }()
					select {
					case <-waiting:
					case <-time.After(10 * time.Second):
						t.Error("the enrolment never waited on the renewal lock")
					}
				}
			}

			// The first holder to release is the delete: its work is done
			// before the lock goes, so the enrolment cannot slip in between.
			released := false
			store.renewLockReleasing = func() {
				mu.Lock()
				first := !released
				released = true
				mu.Unlock()
				if !first {
					return
				}
				if _, err := os.Lstat(store.Dir(deviceRef)); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s released the renewal lock with the credential directory still present (%v)", name, err)
				}
			}

			if err := remove(store, oldSerial); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			// The lock outlives the credential: deleting a held lock file
			// splits later writers across two inodes.
			lockDir, err := store.LockDir(deviceRef)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(lockDir, filepath.Join(store.Root, LocksDir)+string(filepath.Separator)) || strings.Contains(lockDir, deviceRef.Identity) {
				t.Fatalf("lock directory %s, want a hashed name under %s", lockDir, LocksDir)
			}
			if _, err := os.Lstat(filepath.Join(lockDir, lockFile)); err != nil {
				t.Fatalf("renewal lock after %s: %v, want it kept in the lock directory", name, err)
			}
			if err := within(t, saved); err != nil {
				t.Fatalf("SaveIssued while %s held the lock: %v", name, err)
			}
			got, err := store.Load(deviceRef)
			if err != nil {
				t.Fatalf("Load after the enrolment: %v", err)
			}
			if got.Meta.Serial == oldSerial {
				t.Fatalf("the stored serial is the removed one, %s", oldSerial)
			}
			if tomb, err := store.ReadTombstone(deviceRef); err != nil || tomb != nil {
				t.Fatalf("tombstone after the enrolment = %+v, %v; want none", tomb, err)
			}
		})
	}
}

// A lock taken on a file deleted between its open and its lock is not held,
// so a holder that opened the store lock before a purge deleted it never
// believes it excludes the next purge; the next attempt locks a fresh file.
func TestLockOnADeletedFileIsNotHeld(t *testing.T) {
	path := filepath.Join(t.TempDir(), storeLockFile)
	deletes := 1
	lockOpened = func(p string) {
		if deletes > 0 {
			deletes--
			if err := os.Remove(p); err != nil {
				t.Error(err)
			}
		}
	}
	t.Cleanup(func() { lockOpened = nil })

	if release, held, _ := tryLockFile(path, true); held {
		release()
		t.Fatal("a lock on a deleted file counts as held")
	}
	deletes = 1
	release, err := waitLockFile(context.Background(), path, true, time.Second, errors.New("busy"), nil)
	if err != nil {
		t.Fatalf("waitLockFile after a deletion = %v, want the fresh file locked", err)
	}
	release()
}

// A credential lock wanted while a purge holds the store lock is refused with
// ErrStoreBusy, not as a renewal in progress.
func TestStoreLockHeldByAPurgeIsStoreBusy(t *testing.T) {
	ca := newTestCA(t)
	store, _ := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	path, err := store.storeLockPath()
	if err != nil {
		t.Fatal(err)
	}
	release, held, err := tryLockFile(path, false)
	if err != nil || !held {
		t.Fatalf("taking the store lock as a purge does = %v, %v", held, err)
	}
	defer release()
	if _, _, err := store.tryLock(deviceRef); !errors.Is(err, ErrStoreBusy) {
		t.Fatalf("tryLock during a purge = %v, want ErrStoreBusy", err)
	}
	if _, err := store.waitLock(context.Background(), deviceRef, 50*time.Millisecond); !errors.Is(err, ErrStoreBusy) {
		t.Fatalf("waitLock during a purge = %v, want ErrStoreBusy", err)
	}
}

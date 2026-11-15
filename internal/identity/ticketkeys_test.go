package identity

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/localport/agent/internal/security"
)

// loaded runs Load and returns what ticket_keys.json holds.
func (t *TicketKeys) loaded(tb testing.TB) ticketKeysRecord {
	tb.Helper()
	if err := t.Load(); err != nil {
		tb.Fatalf("TicketKeys.Load: %v", err)
	}
	rec, _, _, err := t.read()
	if err != nil {
		tb.Fatalf("read session CA keys: %v", err)
	}
	return rec
}

// mustTicketKeys is TicketKeys for a ref the test knows is a valid device.
func (s *Store) mustTicketKeys(ref Ref) *TicketKeys {
	keys, err := s.TicketKeys(ref)
	if err != nil {
		panic(err)
	}
	return keys
}

// Only a valid device identity has a session CA key store.
func TestTicketKeysRefusesARefThatIsNotADevice(t *testing.T) {
	store := deviceTicketKeys(t)
	for name, ref := range map[string]Ref{
		"user":           {Team: deviceRef.Team, Kind: KindUser, Identity: "alice"},
		"client":         {Team: deviceRef.Team, Kind: KindClient, Identity: "ci"},
		"invalid device": {Team: deviceRef.Team, Kind: KindDevice, Identity: "../gw-01"},
	} {
		if keys, err := store.TicketKeys(ref); !errors.Is(err, ErrNotDeviceIdentity) || keys != nil {
			t.Errorf("%s: TicketKeys = %v, %v, want ErrNotDeviceIdentity", name, keys, err)
		}
	}
}

// assertNoKeysIn fails when a credential metadata file carries session CA keys.
func assertNoKeysIn(tb testing.TB, path string) {
	tb.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		tb.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"keys"`)) || bytes.Contains(raw, []byte("ticket_keys")) {
		tb.Fatalf("%s carries session CA keys:\n%s", filepath.Base(path), raw)
	}
}

func keySet(keys ...TicketKey) DeviceKeys {
	return DeviceKeys{TicketKeys: keys, RecordingKey: testRecordingKey(1)}
}

// testRecordingKey is a valid team recording key derived from 32 copies of
// seed.
func testRecordingKey(seed byte) string {
	priv, err := hpke.MLKEM768X25519().DeriveKeyPair(bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
}

// The held recording key is exposed decoded with its SHA-256. An unusable
// key is refused by Replace and the held key stays.
func TestReplaceValidatesTheRecordingKey(t *testing.T) {
	keys := deviceTicketKeys(t).mustTicketKeys(deviceRef)
	if _, _, ok := keys.RecordingKey(); ok {
		t.Fatal("a key is held before any set")
	}
	if err := keys.Replace(context.Background(), keys.Generation(), keySet(tk1)); err != nil {
		t.Fatal(err)
	}
	want, _ := base64.RawURLEncoding.DecodeString(testRecordingKey(1))
	assertHeldRecordingKey(t, keys, want)
	xwing, _ := base64.RawURLEncoding.DecodeString(testRecordingKey(2))
	for name, key := range map[string]string{
		"padded":         base64.URLEncoding.EncodeToString(xwing),
		"std alphabet":   base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, len(xwing))),
		"not base64":     "!!!!",
		"x25519 only":    base64.RawURLEncoding.EncodeToString(xwing[:32]),
		"one byte short": base64.RawURLEncoding.EncodeToString(xwing[:len(xwing)-1]),
	} {
		if err := keys.Replace(context.Background(), keys.Generation(), DeviceKeys{TicketKeys: []TicketKey{tk2}, RecordingKey: key}); err == nil {
			t.Errorf("%s: Replace accepted it", name)
		}
	}
	assertHeldRecordingKey(t, keys, want)
	assertKIDs(t, keys, []string{"k1"}, []string{"k2"})
	if rec := keys.loaded(t); rec.RecordingKey != testRecordingKey(1) {
		t.Fatalf("file recording key = %q, want the first key", rec.RecordingKey)
	}
}

// A ticket_keys.json whose recording key does not parse still loads its session
// CA keys: the recording key is dropped (reported by ErrRecordingKeyDropped),
// memory keeps the key held before, a fresh process holds none, and the next
// Replace repairs the file.
func TestTicketKeysLoadDropsACorruptRecordingKey(t *testing.T) {
	store := deviceTicketKeys(t)
	keys := store.mustTicketKeys(deviceRef)
	if err := keys.Replace(context.Background(), keys.Generation(), keySet(tk1)); err != nil {
		t.Fatal(err)
	}
	want, _ := base64.RawURLEncoding.DecodeString(testRecordingKey(1))
	body, err := json.Marshal(ticketKeysRecord{Keys: []TicketKey{tk2}, RecordingKey: base64.RawURLEncoding.EncodeToString(make([]byte, 64))})
	if err != nil {
		t.Fatal(err)
	}
	if err := security.WritePrivateFileAtomic(filepath.Join(store.Dir(deviceRef), ticketKeysFile), body); err != nil {
		t.Fatal(err)
	}
	if err := keys.Load(); !errors.Is(err, ErrRecordingKeyDropped) {
		t.Fatalf("Load = %v, want ErrRecordingKeyDropped", err)
	}
	assertKIDs(t, keys, []string{"k2"}, []string{"k1"})
	assertHeldRecordingKey(t, keys, want)

	fresh := (&Store{Root: store.Root}).mustTicketKeys(deviceRef)
	if err := fresh.Load(); !errors.Is(err, ErrRecordingKeyDropped) {
		t.Fatalf("fresh Load = %v, want ErrRecordingKeyDropped", err)
	}
	assertKIDs(t, fresh, []string{"k2"}, nil)
	if _, _, ok := fresh.RecordingKey(); ok {
		t.Fatal("a fresh process holds the dropped recording key")
	}

	if err := fresh.Replace(context.Background(), fresh.Generation(), keySet(tk1)); err != nil {
		t.Fatalf("Replace over the dropped key: %v", err)
	}
	if rec := fresh.loaded(t); rec.RecordingKey != testRecordingKey(1) {
		t.Fatalf("file recording key = %q after Replace, want it repaired", rec.RecordingKey)
	}
	assertHeldRecordingKey(t, fresh, want)
}

func assertHeldRecordingKey(t *testing.T, keys *TicketKeys, want []byte) {
	t.Helper()
	got, sum, ok := keys.RecordingKey()
	if !ok || !bytes.Equal(got, want) || sum != sha256.Sum256(want) {
		t.Fatalf("held recording key ok=%t, matches=%t, sum matches=%t", ok, bytes.Equal(got, want), sum == sha256.Sum256(want))
	}
}

var (
	tk1 = testTicketKey("k1", 1)
	tk2 = testTicketKey("k2", 2)
	tk3 = testTicketKey("k3", 3)
)

// deviceTicketKeys stores a device credential and returns its store.
func deviceTicketKeys(t *testing.T) *Store {
	t.Helper()
	store, _ := savedDevice(t, newTestCA(t), time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	return store
}

func assertKIDs(t *testing.T, keys *TicketKeys, present, absent []string) {
	t.Helper()
	for _, kid := range present {
		if _, ok := keys.Lookup(kid); !ok {
			t.Errorf("Lookup(%s) = absent, want present", kid)
		}
	}
	for _, kid := range absent {
		if _, ok := keys.Lookup(kid); ok {
			t.Errorf("Lookup(%s) = present, want absent", kid)
		}
	}
}

func kidsOf(keys []TicketKey) []string {
	kids := make([]string, len(keys))
	for i, k := range keys {
		kids[i] = k.KID
	}
	return kids
}

// Replace never merges: a kid the API set omits leaves.
func TestReplaceDropsAKidTheSetOmits(t *testing.T) {
	keys := deviceTicketKeys(t).mustTicketKeys(deviceRef)
	if err := keys.Replace(context.Background(), keys.Generation(), keySet(tk1, tk2)); err != nil {
		t.Fatal(err)
	}
	if err := keys.Replace(context.Background(), keys.Generation(), DeviceKeys{TicketKeys: []TicketKey{tk2}, RecordingKey: testRecordingKey(2)}); err != nil {
		t.Fatal(err)
	}
	assertKIDs(t, keys, []string{"k2"}, []string{"k1"})
	if rec := keys.loaded(t); rec.RecordingKey != testRecordingKey(2) {
		t.Fatalf("recording key = %q, want the second key", rec.RecordingKey)
	}
}

// A malformed API set is refused whole and leaves the stored set as it was.
func TestReplaceRefusesAMalformedSet(t *testing.T) {
	keys := deviceTicketKeys(t).mustTicketKeys(deviceRef)
	if err := keys.Replace(context.Background(), keys.Generation(), keySet(tk1)); err != nil {
		t.Fatal(err)
	}
	for name, set := range map[string][]TicketKey{
		"bad kid":       {{KID: "K!", PublicKey: tk2.PublicKey}},
		"short key":     {{KID: "k2", PublicKey: "AAAA"}},
		"not base64url": {{KID: "k2", PublicKey: "+/+/"}},
		"duplicate kid": {tk2, tk2},
	} {
		if err := keys.Replace(context.Background(), keys.Generation(), keySet(set...)); err == nil {
			t.Errorf("%s: Replace accepted it", name)
		}
	}
	assertKIDs(t, keys, []string{"k1"}, []string{"k2"})
}

// An absent file is an empty set; a corrupt one is an error that leaves
// memory as it was, never an empty set.
func TestTicketKeysLoad(t *testing.T) {
	store := deviceTicketKeys(t)
	keys := store.mustTicketKeys(deviceRef)
	if rec := keys.loaded(t); len(rec.Keys) != 0 {
		t.Fatalf("absent file loaded as %+v", rec)
	}
	if err := keys.Replace(context.Background(), keys.Generation(), keySet(tk1)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.Dir(deviceRef), ticketKeysFile)
	for name, body := range map[string]string{
		"not json":      "{",
		"bad key":       `{"keys":[{"kid":"k2","public_key":"AAAA"}]}`,
		"duplicate kid": fmt.Sprintf(`{"keys":[{"kid":"k2","public_key":%q},{"kid":"k2","public_key":%q}]}`, tk2.PublicKey, tk2.PublicKey),
		"bad kid":       fmt.Sprintf(`{"keys":[{"kid":"K!","public_key":%q}]}`, tk2.PublicKey),
	} {
		if err := security.WritePrivateFileAtomic(path, []byte(body)); err != nil {
			t.Fatal(err)
		}
		if err := keys.Load(); err == nil {
			t.Errorf("%s: Load accepted it", name)
		}
		if err := keys.Replace(context.Background(), keys.Generation(), keySet(tk2)); err == nil {
			t.Errorf("%s: Replace wrote over a file it cannot read", name)
		}
		assertKIDs(t, keys, []string{"k1"}, []string{"k2"})
	}
}

// The key file is read with the credential's trust checks.
func TestTicketKeysLoadRefusesAGroupWritableDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits carry no policy on Windows")
	}
	store := deviceTicketKeys(t)
	if err := os.Chmod(store.Dir(deviceRef), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := store.mustTicketKeys(deviceRef).Load(); !errors.Is(err, security.ErrUntrustedPath) {
		t.Fatalf("Load = %v, want ErrUntrustedPath", err)
	}
}

// A meta.json holding keys under device loads; its keys are ignored.
func TestMetaWithKeysFromAnOlderBuildStillLoads(t *testing.T) {
	store := deviceTicketKeys(t)
	path := filepath.Join(store.Dir(deviceRef), metaFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	meta["device"].(map[string]any)["keys"] = testKeys
	if raw, err = json.Marshal(meta); err != nil {
		t.Fatal(err)
	}
	if err := security.WritePrivateFileAtomic(path, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(deviceRef); err != nil {
		t.Fatalf("Load: %v", err)
	}
	keys := store.mustTicketKeys(deviceRef)
	keys.loaded(t)
	assertKIDs(t, keys, nil, []string{"k1"})
}

// A Store hands out one instance per identity; Remove deletes the file and
// forgets the instance.
func TestStoreRemoveDeletesTheTicketKeys(t *testing.T) {
	store := deviceTicketKeys(t)
	keys := store.mustTicketKeys(deviceRef)
	if store.mustTicketKeys(deviceRef) != keys {
		t.Fatal("two instances for one identity")
	}
	if err := keys.Replace(context.Background(), keys.Generation(), keySet(tk1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(context.Background(), deviceRef); err != nil {
		t.Fatal(err)
	}
	fresh := store.mustTicketKeys(deviceRef)
	if fresh == keys {
		t.Fatal("Remove kept the instance")
	}
	fresh.loaded(t)
	assertKIDs(t, fresh, nil, []string{"k1"})
}

func holdAfterRead(keys *TicketKeys) (reached <-chan struct{}, proceed func()) {
	r, p := make(chan struct{}), make(chan struct{})
	var once sync.Once
	keys.afterRead = func() {
		once.Do(func() {
			close(r)
			<-p
		})
	}
	return r, func() { close(p) }
}

// Writers in several goroutines over two stores on one directory never tear
// the file: it always holds one whole set, and each store loads that set.
func TestConcurrentTicketKeyWriters(t *testing.T) {
	store := deviceTicketKeys(t)
	stores := []*TicketKeys{store.mustTicketKeys(deviceRef), (&Store{Root: store.Root}).mustTicketKeys(deviceRef)}
	var sets [][]TicketKey
	for i := range 8 {
		sets = append(sets, []TicketKey{testTicketKey(fmt.Sprintf("k%d", i), byte(i+1)), testTicketKey(fmt.Sprintf("k%d", i+8), byte(i+9))})
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(sets))
	for i, set := range sets {
		keys := stores[i%len(stores)]
		wg.Go(func() { errs <- keys.Replace(context.Background(), keys.Generation(), keySet(set...)) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	rec, _, _, err := stores[0].read()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(sets, func(set []TicketKey) bool { return slices.Equal(set, rec.Keys) }) {
		t.Fatalf("after concurrent writers the file holds %v, not one written set", kidsOf(rec.Keys))
	}
	for _, keys := range stores {
		if got := keys.loaded(t); !slices.Equal(got.Keys, rec.Keys) {
			t.Fatalf("a store loaded %v, the file holds %v", kidsOf(got.Keys), kidsOf(rec.Keys))
		}
	}
}

// A writer in another Store on the same directory (another process) waits
// for .keys.lock before it reads the file, and builds its write from the file
// as the lock holder left it.
func TestKeyWriterInAnotherStoreWaitsForTheFileLock(t *testing.T) {
	store := deviceTicketKeys(t)
	a := store.mustTicketKeys(deviceRef)
	b := (&Store{Root: store.Root}).mustTicketKeys(deviceRef)
	if err := a.Replace(context.Background(), a.Generation(), keySet(tk1, tk2)); err != nil {
		t.Fatal(err)
	}
	aRead, aProceed := holdAfterRead(a)
	replaced := make(chan error, 1)
	go func() { replaced <- a.Replace(context.Background(), a.Generation(), keySet(tk1, tk2, tk3)) }()
	<-aRead

	// b reaches its hook only past .keys.lock. A b without the lock reaches it
	// inside the 200 ms window while a still holds the lock; a b that read the
	// file before a wrote leaves k1 in place of k3 in the final file.
	bRead, bProceed := holdAfterRead(b)
	removed := make(chan error, 1)
	go func() { removed <- b.Replace(context.Background(), b.Generation(), keySet(tk2)) }()
	select {
	case <-bRead:
		t.Fatal("a writer read the file while another Store held .keys.lock")
	case <-time.After(200 * time.Millisecond):
	}
	aProceed()
	if err := <-replaced; err != nil {
		t.Fatal(err)
	}
	bProceed()
	if err := <-removed; err != nil {
		t.Fatal(err)
	}
	rec, _, _, err := a.read()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(kidsOf(rec.Keys), []string{"k2"}) {
		t.Fatalf("after both writers the file holds %+v, want the later writer's keys [k2]", rec)
	}
}

// writeUnreadableTicketKeys leaves ticket_keys.json in a state read refuses:
// a malformed kid, or (on Unix) a mode other than owner-only.
func writeUnreadableTicketKeys(t *testing.T, store *Store, how string) {
	t.Helper()
	path := filepath.Join(store.Dir(deviceRef), ticketKeysFile)
	switch how {
	case "malformed kid":
		if err := security.WritePrivateFileAtomic(path, fmt.Appendf(nil, `{"keys":[{"kid":"K!","public_key":%q}]}`, tk1.PublicKey)); err != nil {
			t.Fatal(err)
		}
	case "mode 0644":
		if runtime.GOOS == "windows" {
			t.Skip("mode bits carry no policy on Windows")
		}
		if err := security.WritePrivateFileAtomic(path, []byte(`{"keys":[]}`)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, err := store.mustTicketKeys(deviceRef).read(); err == nil {
		t.Fatalf("%s: ticket_keys.json still reads", how)
	}
}

// A ticket_keys.json the store cannot read never stops a renewal from storing
// its credential: both renewal paths write pending.json, succeed and log the
// key failure.
func TestRenewalStoresTheCredentialWhenTicketKeysAreUnreadable(t *testing.T) {
	for _, how := range []string{"malformed kid", "mode 0644"} {
		t.Run(how, func(t *testing.T) {
			ca := newTestCA(t)
			store, _ := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
			writeUnreadableTicketKeys(t, store, how)
			srv, _ := renewServer(t, ca, nil)
			var events []string
			r := &Renewer{Store: store, Ref: deviceRef, client: &Client{BaseURL: srv.URL, HTTP: srv.Client()},
				OnEvent: func(e string) { events = append(events, e) }}
			cur, err := store.Load(deviceRef)
			if err != nil {
				t.Fatal(err)
			}

			next, err := r.renewLocked(context.Background(), r.client, cur)
			if err != nil {
				t.Fatalf("renewLocked: %v", err)
			}
			if pending, err := store.LoadPending(deviceRef); err != nil || pending.Meta.Serial != next.Meta.Serial {
				t.Fatalf("pending after renewLocked: %v", err)
			}
			again, err := r.RenewPending(context.Background())
			if err != nil {
				t.Fatalf("RenewPending: %v", err)
			}
			if pending, err := store.LoadPending(deviceRef); err != nil || pending.Meta.Serial != again.Meta.Serial {
				t.Fatalf("pending after RenewPending: %v", err)
			}
			logged := 0
			for _, e := range events {
				if strings.Contains(e, "session CA keys were not stored") && strings.Contains(e, ticketKeysRemedy) {
					logged++
				}
			}
			if logged != 2 {
				t.Fatalf("events %q: want the key failure logged by both renewals", events)
			}
		})
	}
}

const ticketKeysRemedy = "fix the mode of ticket_keys.json to owner-only, or remove it if it is malformed, owned by another user or not a regular file"

// Load refuses a ticket_keys.json it cannot read with ErrTicketKeysUnreadable.
func TestLoadOfAnUnreadableFileIsErrTicketKeysUnreadable(t *testing.T) {
	for _, how := range []string{"malformed kid", "mode 0644"} {
		t.Run(how, func(t *testing.T) {
			store := deviceTicketKeys(t)
			writeUnreadableTicketKeys(t, store, how)
			if err := store.mustTicketKeys(deviceRef).Load(); !errors.Is(err, ErrTicketKeysUnreadable) {
				t.Fatalf("Load = %v, want ErrTicketKeysUnreadable", err)
			}
		})
	}
}

// A renewal whose key set fails for a reason other than reading the file logs
// the error without the file remedy, since the file may be valid.
func TestRenewalLogsAKeyFailureOtherThanReadingWithoutTheRemedy(t *testing.T) {
	store := deviceTicketKeys(t)
	var events []string
	r := &Renewer{Store: store, Ref: deviceRef, OnEvent: func(e string) { events = append(events, e) }}
	r.storeTicketKeys(context.Background(), deviceRef, 0, &Material{DeviceKeys: &DeviceKeys{TicketKeys: []TicketKey{{KID: "K!"}}}})
	if len(events) != 1 || !strings.Contains(events[0], "session CA keys were not stored") || strings.Contains(events[0], ticketKeysRemedy) {
		t.Fatalf("events %q: want the key failure logged once without the file remedy", events)
	}
}

// A refresh-equivalent Replace while a renewal waits on the control plane
// completes at once; the renewal's set, written last, is the one that stays.
func TestReplaceDuringARenewal(t *testing.T) {
	ca := newTestCA(t)
	store, oldKey := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	keys := store.mustTicketKeys(deviceRef)
	inFlight, proceed := make(chan struct{}, 1), make(chan struct{})
	srv, _ := renewServer(t, ca, oldKey, func() {
		inFlight <- struct{}{}
		<-proceed
	})
	r := &Renewer{Store: store, Ref: deviceRef}
	old, err := store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	release, held, err := r.lock()
	if err != nil || !held {
		t.Fatalf("lock: held=%v err=%v", held, err)
	}
	renewed := make(chan error, 1)
	go func() {
		defer release()
		_, err := r.renewLocked(context.Background(), &Client{BaseURL: srv.URL, HTTP: srv.Client()}, old)
		renewed <- err
	}()
	<-inFlight
	if err := keys.Replace(context.Background(), keys.Generation(), keySet(tk2, tk3)); err != nil {
		t.Fatalf("Replace during a renewal: %v", err)
	}
	assertKIDs(t, keys, []string{"k2", "k3"}, []string{"k1"})
	close(proceed)
	if err := <-renewed; err != nil {
		t.Fatal(err)
	}
	rec := keys.loaded(t)
	if !slices.Equal(kidsOf(rec.Keys), []string{"k1"}) {
		t.Fatalf("after the renewal: %+v", rec)
	}
}

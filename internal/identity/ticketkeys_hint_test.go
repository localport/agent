package identity

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// hintedKeys is a device's ticket keys holding set, with a settable clock.
func hintedKeys(t *testing.T, set ...TicketKey) (*TicketKeys, *time.Time) {
	t.Helper()
	keys := deviceTicketKeys(t).mustTicketKeys(deviceRef)
	if err := keys.Replace(context.Background(), keys.Generation(), keySet(set...)); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	keys.now = func() time.Time { return now }
	return keys, &now
}

// A hinted kid is refused until a set requested after the hint settles it; a
// set requested before the hint, such as a fetch already in flight, does not.
func TestHintRefusesAHeldKidUntilALaterSetSettlesIt(t *testing.T) {
	keys, _ := hintedKeys(t, tk1, tk2)
	before := keys.Generation()
	if added, err := keys.Hint([]string{"k1"}); err != nil || !added {
		t.Fatalf("Hint = %v, %v; want added", added, err)
	}
	assertKIDs(t, keys, []string{"k2"}, []string{"k1"})

	if err := keys.Replace(context.Background(), before, keySet(tk1, tk2)); err != nil {
		t.Fatal(err)
	}
	assertKIDs(t, keys, []string{"k2"}, []string{"k1"})

	if err := keys.Replace(context.Background(), keys.Generation(), keySet(tk1, tk2)); err != nil {
		t.Fatal(err)
	}
	assertKIDs(t, keys, []string{"k1", "k2"}, nil)
}

// A hint lasts suspectTTL from its latest repeat when no set settles it.
func TestHintExpires(t *testing.T) {
	keys, now := hintedKeys(t, tk1)
	if _, err := keys.Hint([]string{"k1"}); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(suspectTTL - time.Second)
	if _, err := keys.Hint([]string{"k1"}); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(suspectTTL - time.Second)
	assertKIDs(t, keys, nil, []string{"k1"})
	*now = now.Add(time.Second)
	assertKIDs(t, keys, []string{"k1"}, nil)
}

// A kid the device does not hold is not a hint, and a malformed kid refuses
// the whole list.
func TestHintIgnoresAKidNotHeldAndRefusesAMalformedOne(t *testing.T) {
	keys, _ := hintedKeys(t, tk1)
	if added, err := keys.Hint([]string{"k9"}); err != nil || added {
		t.Fatalf("Hint of a kid not held = %v, %v; want not added", added, err)
	}
	if added, err := keys.Hint([]string{"k1", "../k2"}); err == nil || added {
		t.Fatalf("Hint with a malformed kid = %v, %v; want an error", added, err)
	}
	assertKIDs(t, keys, []string{"k1"}, nil)
	keys.mu.RLock()
	defer keys.mu.RUnlock()
	if len(keys.suspects) != 0 {
		t.Fatalf("suspects %v, want none", keys.suspects)
	}
}

// At most maxSuspects hints are held; a new one drops the oldest.
func TestHintKeepsAtMostMaxSuspects(t *testing.T) {
	var set []TicketKey
	for i := range maxSuspects + 1 {
		set = append(set, testTicketKey(fmt.Sprintf("k%d", i), byte(i+1)))
	}
	keys, now := hintedKeys(t, set...)
	for i := range maxSuspects + 1 {
		*now = now.Add(time.Second)
		if _, err := keys.Hint([]string{set[i].KID}); err != nil {
			t.Fatal(err)
		}
	}
	keys.mu.RLock()
	n := len(keys.suspects)
	keys.mu.RUnlock()
	if n != maxSuspects {
		t.Fatalf("held %d hints, want %d", n, maxSuspects)
	}
	assertKIDs(t, keys, []string{"k0"}, []string{"k1", fmt.Sprintf("k%d", maxSuspects)})
}

// Hints live in memory only: the file keeps the control plane's set.
func TestHintNeverReachesTheFile(t *testing.T) {
	keys, _ := hintedKeys(t, tk1, tk2)
	if _, err := keys.Hint([]string{"k1"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(keys.dir, ticketKeysFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"k1"`) || strings.Contains(string(raw), "revoked") {
		t.Fatalf("ticket_keys.json after a hint: %s", raw)
	}
	other := (&Store{Root: keys.store.Root}).mustTicketKeys(deviceRef)
	if err := other.Load(); err != nil {
		t.Fatal(err)
	}
	assertKIDs(t, other, []string{"k1", "k2"}, nil)
}

// A hint brings the refresher's next fetch to the earliest time the floor
// allows: at once before any fetch, then keyRefreshFloor after the last start.
func TestKeyRefresherHintBringsTheNextFetchToTheFloor(t *testing.T) {
	var hits atomic.Int32
	f := startKeyRefresher(t, newServer(t, keysHandler(&hits, keySet(tk1))), tk1)
	f.run(t)
	assertRefreshWait(t, within(t, f.clock.armed))

	// No fetch has run yet, so the hint starts one at once; its end arms the
	// scheduled refresh.
	f.r.Hint()
	assertRefreshWait(t, within(t, f.clock.armed))
	if hits.Load() != 1 {
		t.Fatalf("fetches = %d, want 1", hits.Load())
	}

	f.r.Hint()
	if d := within(t, f.clock.armed); d != keyRefreshFloor {
		t.Fatalf("after a hint inside the floor the wait is %s, want %s", d, keyRefreshFloor)
	}
}

// A hint while a fetch is in flight: that fetch does not settle it, and its
// end schedules the next fetch at the floor rather than in keyRefreshInterval.
func TestKeyRefresherHintDuringAFetchKeepsTheNextFetchAtTheFloor(t *testing.T) {
	var hits atomic.Int32
	reached, release := make(chan struct{}), make(chan struct{})
	handler := keysHandler(&hits, keySet(tk1, tk2))
	f := startKeyRefresher(t, newServer(t, func(w http.ResponseWriter, r *http.Request) {
		reached <- struct{}{}
		<-release
		handler(w, r)
	}), tk1, tk2)
	f.run(t)
	assertRefreshWait(t, within(t, f.clock.armed))

	fetched := make(chan error, 1)
	go func() { fetched <- f.r.RefreshNow(context.Background()) }()
	within(t, reached)
	if added, err := f.keys.Hint([]string{"k1"}); err != nil || !added {
		t.Fatalf("Hint = %v, %v", added, err)
	}
	f.r.Hint()
	close(release)
	if err := within(t, fetched); err != nil {
		t.Fatal(err)
	}
	assertKIDs(t, f.keys, []string{"k2"}, []string{"k1"})
	if d := within(t, f.clock.armed); d != keyRefreshFloor {
		t.Fatalf("next fetch after a hinted fetch in %s, want %s", d, keyRefreshFloor)
	}
}

// A hint given before Run starts, as from a RegisterAck that arrives before
// the refresher's goroutine runs, makes Run fetch at once.
func TestKeyRefresherHintBeforeRunFetchesAtOnce(t *testing.T) {
	var hits atomic.Int32
	f := startKeyRefresher(t, newServer(t, keysHandler(&hits, keySet(tk1))), tk1)
	f.r.Hint()
	f.run(t)
	assertRefreshWait(t, within(t, f.clock.armed))
	if hits.Load() != 1 {
		t.Fatalf("fetches = %d, want 1 at start", hits.Load())
	}
}

// A renewal whose request started before a hint does not settle it, though
// its set lists the kid: only a set requested after the hint does.
func TestRenewalStartedBeforeAHintDoesNotSettleIt(t *testing.T) {
	ca := newTestCA(t)
	store, oldKey := savedDevice(t, ca, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	keys := store.mustTicketKeys(deviceRef)
	if err := keys.Replace(context.Background(), keys.Generation(), testKeys); err != nil {
		t.Fatal(err)
	}
	srv, _ := renewServer(t, ca, oldKey, func() {
		if _, err := keys.Hint([]string{"k1"}); err != nil {
			t.Error(err)
		}
	})
	r := &Renewer{Store: store, Ref: deviceRef}
	cur, err := store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	release, held, err := r.lock()
	if err != nil || !held {
		t.Fatalf("lock: held=%v err=%v", held, err)
	}
	_, err = r.renewLocked(context.Background(), &Client{BaseURL: srv.URL, HTTP: srv.Client()}, cur)
	release()
	if err != nil {
		t.Fatal(err)
	}
	assertKIDs(t, keys, nil, []string{"k1"})
	if err := keys.Replace(context.Background(), keys.Generation(), testKeys); err != nil {
		t.Fatal(err)
	}
	assertKIDs(t, keys, []string{"k1"}, nil)
}

// A ticket_keys.json holding a revoked list loads; the list is ignored.
func TestTicketKeysLoadIgnoresALegacyRevokedList(t *testing.T) {
	store := deviceTicketKeys(t)
	keys := store.mustTicketKeys(deviceRef)
	if err := keys.Replace(context.Background(), keys.Generation(), keySet(tk1)); err != nil {
		t.Fatal(err)
	}
	legacy := fmt.Sprintf(`{"keys":[{"kid":"k1","public_key":%q}],"revoked":["k2"],"recording_key":""}`, tk1.PublicKey)
	if err := os.WriteFile(filepath.Join(store.Dir(deviceRef), ticketKeysFile), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := keys.Load(); err != nil {
		t.Fatalf("Load of a legacy file: %v", err)
	}
	assertKIDs(t, keys, []string{"k1"}, nil)
}

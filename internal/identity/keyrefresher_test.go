package identity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// fakeKeyClock is a keyClock whose time moves only on Advance. Every armed
// timer's duration is sent on armed, so a test knows when Run is waiting.
type fakeKeyClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeKeyTimer
	armed  chan time.Duration
}

type fakeKeyTimer struct {
	at   time.Time
	c    chan time.Time
	done bool
}

func newFakeKeyClock() *fakeKeyClock {
	return &fakeKeyClock{now: time.Unix(1_800_000_000, 0), armed: make(chan time.Duration, 256)}
}

func (c *fakeKeyClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeKeyClock) NewTimer(d time.Duration) (<-chan time.Time, func() bool) {
	c.mu.Lock()
	t := &fakeKeyTimer{at: c.now.Add(d), c: make(chan time.Time, 1)}
	c.timers = append(c.timers, t)
	c.mu.Unlock()
	c.armed <- d
	return t.c, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		was := !t.done
		t.done = true
		return was
	}
}

// Advance moves the clock and fires every timer now due.
func (c *fakeKeyClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for _, t := range c.timers {
		if !t.done && !t.at.After(c.now) {
			t.done = true
			t.c <- c.now
		}
	}
}

// within returns the next value from ch, failing the test after 10 seconds.
func within[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting")
		var zero T
		return zero
	}
}

func assertRefreshWait(t *testing.T, d time.Duration) {
	t.Helper()
	if d < keyRefreshInterval*9/10 || d > keyRefreshInterval*11/10 {
		t.Fatalf("scheduled wait = %s, want 6h ±10%%", d)
	}
}

func assertBackoff(t *testing.T, d, base time.Duration) {
	t.Helper()
	if d < base*4/5 || d > base*6/5 {
		t.Fatalf("backoff wait = %s, want %s ±20%%", d, base)
	}
}

func TestBackoffWaitJitterIsProportional(t *testing.T) {
	for _, base := range []time.Duration{minKeyRetry, maxKeyRetry} {
		lo, hi := base, base
		for range 1000 {
			d := backoffWait(base)
			assertBackoff(t, d, base)
			lo, hi = min(lo, d), max(hi, d)
		}
		// 1000 uniform draws over ±20 % cover more than ±15 %.
		if lo > base*85/100 || hi < base*115/100 {
			t.Fatalf("backoffWait(%s) drew only [%s, %s], want a spread near ±20%%", base, lo, hi)
		}
	}
}

// refresherFixture is a device store, a refresher reaching srv and a fake
// clock. seed, when given, is stored as the key set before Run starts.
type refresherFixture struct {
	store *Store
	clock *fakeKeyClock
	r     *KeyRefresher
	keys  *TicketKeys
	stop  context.CancelFunc
	done  chan struct{}
}

func startKeyRefresher(t *testing.T, srv *httptest.Server, seed ...TicketKey) *refresherFixture {
	t.Helper()
	return newRefresherFixture(t, &Client{BaseURL: srv.URL, HTTP: srv.Client()}, seed...)
}

// newRefresherFixture is startKeyRefresher with the refresher reaching the
// control plane through client.
func newRefresherFixture(t *testing.T, client *Client, seed ...TicketKey) *refresherFixture {
	t.Helper()
	store := deviceTicketKeys(t)
	keys := store.mustTicketKeys(deviceRef)
	if len(seed) > 0 {
		if err := keys.Replace(context.Background(), keys.Generation(), keySet(seed...)); err != nil {
			t.Fatal(err)
		}
	}
	f := &refresherFixture{store: store, clock: newFakeKeyClock(), keys: keys, done: make(chan struct{})}
	f.r = &KeyRefresher{
		Store:   store,
		Ref:     deviceRef,
		OnEvent: func(line string) { t.Log(line) },
		client:  client,
		clock:   f.clock,
	}
	return f
}

func (f *refresherFixture) run(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	f.stop = cancel
	go func() {
		f.r.Run(ctx)
		close(f.done)
	}()
	t.Cleanup(func() {
		cancel()
		<-f.done
	})
}

// keysHandler answers /v1/devices/keys with set and counts requests.
func keysHandler(hits *atomic.Int32, set DeviceKeys) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": set})
	}
}

func newServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// The digest is built here byte by byte as the control plane builds it:
// context, the bucket as 8 bytes big-endian, then the serial's hex text.
func TestDeviceKeysDigestMatchesTheServerConstruction(t *testing.T) {
	msg := []byte("localport-device-keys-v1")
	msg = append(msg, 0, 0, 0, 0, 0x01, 0xBA, 0x81, 0x40) // 29000000
	msg = append(msg, "beef"...)
	want := sha256.Sum256(msg)
	if got := deviceKeysDigest(29000000, "beef"); !bytes.Equal(got, want[:]) {
		t.Fatalf("digest = %x, want %x", got, want)
	}
}

func TestFetchDeviceKeysSendsTheCertificateAndASignedProof(t *testing.T) {
	store, key := savedDevice(t, newTestCA(t), time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	cur, err := store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/devices/keys" {
			t.Errorf("request = %s %s, want POST /v1/devices/keys", r.Method, r.URL.Path)
		}
		var body struct {
			CertPEM   string `json:"cert_pem"`
			Signature string `json:"signature"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			t.Errorf("body: %v", err)
		}
		leaf, err := leafOf([]byte(body.CertPEM))
		if err != nil {
			t.Fatal(err)
		}
		want, _ := leafOf(cur.CertPEM)
		if !leaf.Equal(want) {
			t.Error("cert_pem is not the current certificate")
		}
		sig, err := base64.StdEncoding.DecodeString(body.Signature)
		if err != nil {
			t.Errorf("signature is not standard base64: %v", err)
		}
		serial, bucket := leaf.SerialNumber.Text(16), time.Now().Unix()/60
		if !ecdsa.VerifyASN1(&key.PublicKey, deviceKeysDigest(bucket, serial), sig) &&
			!ecdsa.VerifyASN1(&key.PublicKey, deviceKeysDigest(bucket-1, serial), sig) {
			t.Error("signature does not verify over the device keys digest")
		}
		keysHandler(new(atomic.Int32), testKeys)(w, r)
	})

	got, err := (&Client{BaseURL: srv.URL, HTTP: srv.Client()}).FetchDeviceKeys(context.Background(), cur)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*got, testKeys) {
		t.Fatalf("keys = %+v, want %+v", *got, testKeys)
	}
}

// A response without a ticket key set must not reach Replace, which would
// empty the set; an empty array is a valid set.
func TestFetchDeviceKeysRefusesAResponseWithoutKeys(t *testing.T) {
	store, _ := savedDevice(t, newTestCA(t), time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	cur, err := store.Load(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	fetch := func(body string) (*DeviceKeys, error) {
		srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		})
		return (&Client{BaseURL: srv.URL, HTTP: srv.Client()}).FetchDeviceKeys(context.Background(), cur)
	}
	for _, body := range []string{`{}`, `{"keys":null}`, `{"keys":{}}`, `{"keys":{"ticket_keys":null,"recording_key":"r"}}`} {
		if _, err := fetch(body); !errors.Is(err, ErrNoTicketKeys) {
			t.Errorf("FetchDeviceKeys(%s) = %v, want ErrNoTicketKeys", body, err)
		}
	}
	got, err := fetch(`{"keys":{"ticket_keys":[],"recording_key":"r"}}`)
	if err != nil || got.TicketKeys == nil || len(got.TicketKeys) != 0 {
		t.Fatalf("FetchDeviceKeys(empty set) = %+v, %v, want an empty set", got, err)
	}
}

func TestKeyRefresherFetchesAtStartOnlyWhenTheSetIsEmpty(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		var hits atomic.Int32
		f := startKeyRefresher(t, newServer(t, keysHandler(&hits, keySet(tk1))))
		f.run(t)
		assertRefreshWait(t, within(t, f.clock.armed))
		if hits.Load() != 1 {
			t.Fatalf("fetches = %d, want 1", hits.Load())
		}
		if _, ok := f.keys.Lookup("k1"); !ok {
			t.Fatal("the fetched set was not stored")
		}
	})
	t.Run("not empty", func(t *testing.T) {
		var hits atomic.Int32
		f := startKeyRefresher(t, newServer(t, keysHandler(&hits, keySet(tk1))), tk2)
		f.run(t)
		assertRefreshWait(t, within(t, f.clock.armed))
		if hits.Load() != 0 {
			t.Fatalf("fetches = %d, want none", hits.Load())
		}
	})
}

// Callers arriving while a fetch is in flight wait for it and get its result.
func TestRefreshNowSharesOneFetch(t *testing.T) {
	const callers = 5
	var hits atomic.Int32
	entered, release := make(chan struct{}, callers), make(chan struct{})
	f := startKeyRefresher(t, newServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusForbidden)
	}), tk1)
	decided := make(chan struct{}, callers)
	f.r.decided = func() { decided <- struct{}{} }
	f.run(t)
	within(t, f.clock.armed)

	errs := make(chan error, callers)
	refresh := func() { errs <- f.r.RefreshNow(context.Background()) }
	go refresh()
	within(t, entered)
	within(t, decided)
	for range callers - 1 {
		go refresh()
	}
	for range callers - 1 {
		within(t, decided)
	}
	close(release)

	for range callers {
		var apiErr *APIError
		if err := within(t, errs); !errors.As(err, &apiErr) || apiErr.Status != http.StatusForbidden {
			t.Errorf("RefreshNow = %v, want the shared fetch's 403", err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("fetches = %d, want 1", hits.Load())
	}
}

func TestRefreshNowFetchesAtMostOncePerFloor(t *testing.T) {
	var hits atomic.Int32
	f := startKeyRefresher(t, newServer(t, keysHandler(&hits, keySet(tk2))), tk1)
	f.run(t)
	within(t, f.clock.armed)

	if err := f.r.RefreshNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	within(t, f.clock.armed)
	f.clock.Advance(keyRefreshFloor - time.Second)
	if err := f.r.RefreshNow(context.Background()); err != nil {
		t.Fatalf("RefreshNow inside the floor = %v, want the last fetch's nil", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("fetches inside the floor = %d, want 1", hits.Load())
	}
	f.clock.Advance(time.Second)
	if err := f.r.RefreshNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Fatalf("fetches after the floor = %d, want 2", hits.Load())
	}
}

// A caller giving up does not cancel the fetch it shares: the result is stored.
func TestRefreshNowCallerCancelLeavesTheFetchRunning(t *testing.T) {
	var hits atomic.Int32
	entered, release := make(chan struct{}, 1), make(chan struct{})
	f := startKeyRefresher(t, newServer(t, func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		keysHandler(&hits, keySet(tk2))(w, r)
	}), tk1)
	f.run(t)
	within(t, f.clock.armed)

	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() { errs <- f.r.RefreshNow(ctx) }()
	within(t, entered)
	cancel()
	if err := within(t, errs); !errors.Is(err, context.Canceled) {
		t.Fatalf("RefreshNow = %v, want context.Canceled", err)
	}
	close(release)
	assertRefreshWait(t, within(t, f.clock.armed))

	if hits.Load() != 1 {
		t.Fatalf("fetches answered = %d, want 1", hits.Load())
	}
	if _, ok := f.keys.Lookup("k2"); !ok {
		t.Fatal("the shared fetch's set was not stored")
	}
	if _, ok := f.keys.Lookup("k1"); ok {
		t.Fatal("the replaced set is still held")
	}
}

// Failures keep the set and back off 1m, 2m...; a success resets the backoff.
func TestKeyRefresherBacksOffAndASuccessResetsIt(t *testing.T) {
	var mu sync.Mutex
	script := []int{http.StatusForbidden, http.StatusForbidden, http.StatusOK, http.StatusForbidden}
	f := startKeyRefresher(t, newServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		status := script[0]
		script = script[1:]
		mu.Unlock()
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		keysHandler(new(atomic.Int32), keySet(tk2))(w, r)
	}), tk1)
	f.run(t)

	d := within(t, f.clock.armed)
	assertRefreshWait(t, d)
	f.clock.Advance(d)
	d = within(t, f.clock.armed)
	assertBackoff(t, d, minKeyRetry)
	if _, ok := f.keys.Lookup("k1"); !ok {
		t.Fatal("a failed fetch dropped the set")
	}
	var apiErr *APIError
	if err := f.r.RefreshNow(context.Background()); !errors.As(err, &apiErr) {
		t.Fatalf("RefreshNow inside the floor = %v, want the failed fetch's error", err)
	}

	f.clock.Advance(d)
	d = within(t, f.clock.armed)
	assertBackoff(t, d, 2*minKeyRetry)

	f.clock.Advance(d)
	d = within(t, f.clock.armed)
	assertRefreshWait(t, d)
	if _, ok := f.keys.Lookup("k2"); !ok {
		t.Fatal("the fetched set was not stored")
	}

	f.clock.Advance(d)
	assertBackoff(t, within(t, f.clock.armed), minKeyRetry)
}

// OnEvent runs without the refresher's lock, so it may call RefreshNow.
func TestKeyRefresherOnEventMayCallRefreshNow(t *testing.T) {
	f := startKeyRefresher(t, newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	got := make(chan error, 4)
	f.r.OnEvent = func(string) { got <- f.r.RefreshNow(context.Background()) }
	f.run(t)
	var apiErr *APIError
	if err := within(t, got); !errors.As(err, &apiErr) || apiErr.Status != http.StatusForbidden {
		t.Fatalf("RefreshNow from OnEvent = %v, want the failed fetch's 403", err)
	}
}

// A Replace failure is a failed fetch: it keeps the stored set, names the file
// remedy and backs off.
func TestKeyRefresherReplaceFailureBacksOffWithTheRemedy(t *testing.T) {
	var hits atomic.Int32
	f := startKeyRefresher(t, newServer(t, keysHandler(&hits, keySet(tk2))), tk1)
	f.run(t)
	within(t, f.clock.armed)
	writeUnreadableTicketKeys(t, f.store, "malformed kid")

	err := f.r.RefreshNow(context.Background())
	if !errors.Is(err, ErrTicketKeysUnreadable) || !strings.Contains(err.Error(), ticketKeysRemedy) {
		t.Fatalf("RefreshNow = %v, want ErrTicketKeysUnreadable with the remedy", err)
	}
	assertBackoff(t, within(t, f.clock.armed), minKeyRetry)
	if hits.Load() != 1 {
		t.Fatalf("fetches = %d, want 1", hits.Load())
	}
}

// An unreadable ticket_keys.json at start counts as empty: Run fetches at once,
// the store fails and the backoff paces the retries.
func TestKeyRefresherFetchesAtStartWhenTheFileIsUnreadable(t *testing.T) {
	var hits atomic.Int32
	f := startKeyRefresher(t, newServer(t, keysHandler(&hits, keySet(tk2))))
	writeUnreadableTicketKeys(t, f.store, "malformed kid")
	f.run(t)
	assertBackoff(t, within(t, f.clock.armed), minKeyRetry)
	if hits.Load() != 1 {
		t.Fatalf("fetches = %d, want 1", hits.Load())
	}
	if err := f.r.RefreshNow(context.Background()); !errors.Is(err, ErrTicketKeysUnreadable) {
		t.Fatalf("RefreshNow inside the floor = %v, want the failed store's ErrTicketKeysUnreadable", err)
	}
}

// roundTripFunc is an http.RoundTripper made of a function.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The transport ignores the request's context and holds the fetch until
// released, so the fetch outlives Run's cancel. synctest.Wait returns once
// every goroutine in the bubble is durably blocked, so Run has then either
// returned or parked in its join on the held fetch.
func TestKeyRefresherRunJoinsItsFetchOnCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered := make(chan struct{})
		release := make(chan struct{})
		held := roundTripFunc(func(*http.Request) (*http.Response, error) {
			close(entered)
			<-release
			return nil, errors.New("fetch released after Run's cancel")
		})
		f := newRefresherFixture(t, &Client{BaseURL: "https://control.invalid", HTTP: &http.Client{Transport: held}}, tk1)
		f.run(t)
		// Runs before f.run's cleanup, so a failed test leaves no goroutine held.
		releaseFetch := sync.OnceFunc(func() { close(release) })
		t.Cleanup(releaseFetch)
		<-f.clock.armed

		errs := make(chan error, 1)
		go func() { errs <- f.r.RefreshNow(context.Background()) }()
		<-entered
		f.stop()
		synctest.Wait()
		select {
		case <-f.done:
			t.Fatal("Run returned while its fetch was in flight")
		default:
		}

		releaseFetch()
		<-f.done
		if err := <-errs; err == nil {
			t.Fatal("the fetch cut short by Run's cancel reported success")
		}
		f.r.mu.Lock()
		inflight := f.r.inflight
		f.r.mu.Unlock()
		if inflight != nil {
			t.Fatal("Run returned with a fetch in flight")
		}
		if err := f.r.RefreshNow(context.Background()); !errors.Is(err, ErrKeyRefresherStopped) {
			t.Fatalf("RefreshNow after Run = %v, want ErrKeyRefresherStopped", err)
		}
	})
}

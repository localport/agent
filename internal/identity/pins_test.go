package identity

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/localport/agent/internal/security"
)

func pinKey(s string) [32]byte { return sha256.Sum256([]byte(s)) }

func (s *Store) mustDesktopPins(t *testing.T) *DesktopPins {
	t.Helper()
	p, err := s.DesktopPins(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mustPin(t *testing.T, p *DesktopPins, target, key string) PinResult {
	t.Helper()
	r, err := p.Pin(context.Background(), "vnc", target, pinKey(key))
	if err != nil {
		t.Fatalf("Pin(%s, %s): %v", target, key, err)
	}
	return r
}

// The first key a target presents is pinned; the same key matches, another
// is refused and leaves the pin; another target starts a new pin; Reset
// removes it so the next key is pinned again. Lookup reports the pin.
func TestDesktopPins(t *testing.T) {
	store := deviceTicketKeys(t)
	pins := store.mustDesktopPins(t)
	if store.mustDesktopPins(t) != pins {
		t.Fatal("two instances for one identity")
	}
	if _, held, err := pins.Lookup("vnc", "127.0.0.1:5900"); err != nil || held {
		t.Fatalf("Lookup before any pin = %v, %v", held, err)
	}
	for _, step := range []struct {
		target, key string
		want        PinResult
	}{
		{"127.0.0.1:5900", "a", PinNew},
		{"127.0.0.1:5900", "a", PinMatch},
		{"127.0.0.1:5900", "b", PinChanged},
		{"127.0.0.1:5900", "a", PinMatch},
		{"127.0.0.1:5901", "b", PinNew},
		{"127.0.0.1:5901", "a", PinChanged},
	} {
		if got := mustPin(t, pins, step.target, step.key); got != step.want {
			t.Fatalf("Pin(%s, %s) = %v, want %v", step.target, step.key, got, step.want)
		}
	}
	if key, held, err := pins.Lookup("vnc", "127.0.0.1:5901"); err != nil || !held || key != pinKey("b") {
		t.Fatalf("Lookup = %x, %v, %v; want the pinned key", key, held, err)
	}
	if _, held, _ := pins.Lookup("vnc", "127.0.0.1:5900"); held {
		t.Fatal("Lookup of the replaced target reports a pin")
	}
	if r, err := pins.Pin(context.Background(), "rdp", "127.0.0.1:3389", pinKey("c")); err != nil || r != PinNew {
		t.Fatalf("rdp Pin = %v, %v", r, err)
	}
	if r, err := pins.Reset(context.Background(), "vnc"); err != nil || r != ResetForgot {
		t.Fatalf("Reset = %v, %v; want ResetForgot", r, err)
	}
	if r, err := pins.Reset(context.Background(), "vnc"); err != nil || r != ResetNone {
		t.Fatalf("second Reset = %v, %v; want ResetNone", r, err)
	}
	if got := mustPin(t, pins, "127.0.0.1:5901", "a"); got != PinNew {
		t.Fatalf("Pin after Reset = %v, want PinNew", got)
	}
	if r, _ := pins.Pin(context.Background(), "rdp", "127.0.0.1:3389", pinKey("c")); r != PinMatch {
		t.Fatalf("Reset of vnc touched rdp: %v", r)
	}
	pinPath := filepath.Join(store.Dir(deviceRef), desktopPinsFile)
	// Go derives no mode bits from a DACL: on Windows the private-file
	// check reads the DACL instead.
	if runtime.GOOS == "windows" {
		if _, err := security.ReadPrivateFile(pinPath); err != nil {
			t.Fatalf("pin file: %v", err)
		}
		return
	}
	info, err := os.Stat(pinPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("pin file mode %v, %v; want 0600", info.Mode(), err)
	}
}

// Only a device identity holds desktop pins.
func TestDesktopPinsRefuseARefThatIsNotADevice(t *testing.T) {
	store := deviceTicketKeys(t)
	ref := deviceRef
	ref.Kind = KindUser
	if _, err := store.DesktopPins(ref); !errors.Is(err, ErrNotDeviceIdentity) {
		t.Fatalf("DesktopPins(user) = %v, want ErrNotDeviceIdentity", err)
	}
}

// A corrupt or untrusted pin file refuses every lookup and pin; it is never
// an empty set. Reset removes it, after which pins start empty.
func TestDesktopPinsRefuseACorruptFile(t *testing.T) {
	store := deviceTicketKeys(t)
	path := filepath.Join(store.Dir(deviceRef), desktopPinsFile)
	for _, tc := range []struct {
		content string
		mode    os.FileMode
	}{
		{"{", 0o600},
		{`{"vnc":{"target":"127.0.0.1:5900","key_sha256":"zz"}}`, 0o600},
		{`{"vnc":{"target":"","key_sha256":""}}`, 0o600},
		{`{}`, 0o644},
	} {
		if tc.mode != 0o600 && runtime.GOOS == "windows" {
			continue
		}
		if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, tc.mode); err != nil {
			t.Fatal(err)
		}
		pins := store.mustDesktopPins(t)
		if _, _, err := pins.Lookup("vnc", "127.0.0.1:5900"); !errors.Is(err, ErrDesktopPinsUnreadable) {
			t.Fatalf("Lookup over %q %v = %v, want ErrDesktopPinsUnreadable", tc.content, tc.mode, err)
		}
		if _, err := pins.Pin(context.Background(), "vnc", "127.0.0.1:5900", pinKey("a")); !errors.Is(err, ErrDesktopPinsUnreadable) {
			t.Fatalf("Pin over %q %v = %v, want ErrDesktopPinsUnreadable", tc.content, tc.mode, err)
		}
		if r, err := pins.Reset(context.Background(), "vnc"); err != nil || r != ResetDiscarded {
			t.Fatalf("Reset over %q %v = %v, %v; want ResetDiscarded", tc.content, tc.mode, r, err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Reset over %q %v left the file: %v", tc.content, tc.mode, err)
		}
		if got := mustPin(t, pins, "127.0.0.1:5900", "a"); got != PinNew {
			t.Fatalf("Pin after the discard = %v, want PinNew", got)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
}

// Reset never removes a pin file in an untrusted directory.
func TestDesktopPinResetKeepsAFileInAnUntrustedDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory modes are Unix trust rules")
	}
	store := deviceTicketKeys(t)
	pins := store.mustDesktopPins(t)
	mustPin(t, pins, "127.0.0.1:5900", "a")
	dir := store.Dir(deviceRef)
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := pins.Reset(context.Background(), "vnc"); !errors.Is(err, ErrDesktopPinsUnreadable) {
		t.Fatalf("Reset in an untrusted directory = %v, want ErrDesktopPinsUnreadable", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, desktopPinsFile)); err != nil {
		t.Fatalf("Reset in an untrusted directory removed the file: %v", err)
	}
}

// The discard decision uses the trust result of the read it follows: a
// directory made private after an untrusted read does not turn the refusal
// into a removal of a valid pin file.
func TestDesktopPinResetDecidesTrustOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory modes are Unix trust rules")
	}
	store := deviceTicketKeys(t)
	pins := store.mustDesktopPins(t)
	mustPin(t, pins, "127.0.0.1:5900", "a")
	dir := store.Dir(deviceRef)
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	pins.afterRead = func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Error(err)
		}
	}
	if _, err := pins.Reset(context.Background(), "vnc"); !errors.Is(err, ErrDesktopPinsUnreadable) {
		t.Fatalf("Reset after an untrusted read = %v, want ErrDesktopPinsUnreadable", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, desktopPinsFile)); err != nil {
		t.Fatalf("Reset removed a valid pin file after an untrusted read: %v", err)
	}
}

// Concurrent first-use pins with different keys, from two stores on one
// directory (as two processes would be), pin exactly one key.
func TestConcurrentDesktopPins(t *testing.T) {
	store := deviceTicketKeys(t)
	other := &Store{Root: store.Root}
	for round := range 5 {
		if _, err := store.mustDesktopPins(t).Reset(context.Background(), "vnc"); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		results := make([]PinResult, 8)
		for i := range results {
			s := store
			if i%2 == 1 {
				s = other
			}
			wg.Go(func() {
				p, err := s.DesktopPins(deviceRef)
				if err == nil {
					results[i], err = p.Pin(context.Background(), "vnc", "127.0.0.1:5900", pinKey(string(rune('a'+i))))
				}
				if err != nil {
					t.Errorf("round %d pin %d: %v", round, i, err)
				}
			})
		}
		wg.Wait()
		news := 0
		for _, r := range results {
			switch r {
			case PinNew:
				news++
			case PinChanged:
			default:
				t.Fatalf("round %d: result %v, want PinNew or PinChanged", round, r)
			}
		}
		if news != 1 {
			t.Fatalf("round %d: %d pins written, want exactly 1", round, news)
		}
	}
}

// A pin waiting for another process's lock stops when its context ends.
func TestDesktopPinWaitIsCancellable(t *testing.T) {
	store := deviceTicketKeys(t)
	release, held, err := tryLockFile(filepath.Join(store.Dir(deviceRef), desktopPinsLockFile))
	if err != nil || !held {
		t.Fatalf("hold the lock: %v, %v", held, err)
	}
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.mustDesktopPins(t).Pin(ctx, "vnc", "127.0.0.1:5900", pinKey("a")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Pin with the lock held and ctx cancelled = %v, want context.Canceled", err)
	}
}

// Removing the identity removes its pins and the cached instance, and a pin
// never recreates the removed directory.
func TestStoreRemoveDeletesTheDesktopPins(t *testing.T) {
	store := deviceTicketKeys(t)
	pins := store.mustDesktopPins(t)
	mustPin(t, pins, "127.0.0.1:5900", "a")
	if err := store.Remove(context.Background(), deviceRef); err != nil {
		t.Fatal(err)
	}
	if store.mustDesktopPins(t) == pins {
		t.Fatal("Remove kept the instance")
	}
	if _, err := pins.Pin(context.Background(), "vnc", "127.0.0.1:5900", pinKey("a")); err == nil {
		t.Fatal("a pin after Remove succeeded")
	}
	if _, err := os.Stat(store.Dir(deviceRef)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("identity directory after Remove and a pin: %v", err)
	}
}

// A pin writer in another Store waits for .pins.lock: it cannot read the file
// while the first writer holds the lock between its read and its write, so
// only the first writer pins.
func TestDesktopPinWriterInAnotherStoreWaitsForTheFileLock(t *testing.T) {
	store := deviceTicketKeys(t)
	a := store.mustDesktopPins(t)
	b, err := (&Store{Root: store.Root}).DesktopPins(deviceRef)
	if err != nil {
		t.Fatal(err)
	}
	hold := func(p *DesktopPins) (reached <-chan struct{}, proceed func()) {
		r, c := make(chan struct{}), make(chan struct{})
		var once sync.Once
		p.afterRead = func() {
			once.Do(func() {
				close(r)
				<-c
			})
		}
		return r, func() { close(c) }
	}
	aRead, aProceed := hold(a)
	aDone := make(chan PinResult, 1)
	go func() {
		r, _ := a.Pin(context.Background(), "vnc", "127.0.0.1:5900", pinKey("a"))
		aDone <- r
	}()
	<-aRead
	bRead, bProceed := hold(b)
	bDone := make(chan PinResult, 1)
	go func() {
		r, _ := b.Pin(context.Background(), "vnc", "127.0.0.1:5900", pinKey("b"))
		bDone <- r
	}()
	select {
	case <-bRead:
		t.Fatal("a writer read the pins while another Store held .pins.lock")
	case <-time.After(200 * time.Millisecond):
	}
	aProceed()
	bProceed()
	if ra, rb := <-aDone, <-bDone; ra != PinNew || rb != PinChanged {
		t.Fatalf("results %v, %v; want PinNew then PinChanged", ra, rb)
	}
}

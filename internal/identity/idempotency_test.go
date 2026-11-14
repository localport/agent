package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"testing"
)

// idempotencyKeySyntax is a Structured Field String holding the base32 text
// of crypto/rand.Text (research R12).
var idempotencyKeySyntax = regexp.MustCompile(`^"[A-Z2-7]{26}"$`)

// One MintSession call keeps its key across a body read failure after a 2xx
// and an in-flight 409, and accepts the stored-result replay; the next call
// carries a new key.
func TestIdempotencyKeyIsKeptAcrossRetriesAndNewPerCall(t *testing.T) {
	cur := credentialFor(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/user/ana")
	want := SessionCertificate{Certificate: "ssh-ed25519-cert-v01@openssh.com AAAA", URL: "wss://edge/v1/session", HostKey: "ecdsa-sha2-nistp256 AAAA", DeviceHost: "gw-01-factory.eu.localport.dev"}
	full, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var keys []string
	var bodies []mintSessionBody
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body mintSessionBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("body: %v", err)
		}
		mu.Lock()
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		bodies = append(bodies, body)
		attempt := len(keys)
		mu.Unlock()

		switch attempt {
		case 1:
			// The answer is lost after the server committed it: the declared
			// length is never reached and the connection closes.
			w.Header().Set("Content-Length", strconv.Itoa(len(full)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(full[:len(full)/2])
			w.(http.Flusher).Flush()
		case 2:
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": codeIdempotencyInFlight, "message": "in flight"})
		default:
			// Attempt 3 is the stored-result replay; attempt 4 is the next call.
			_, _ = w.Write(full)
		}
	})
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	req := SessionRequest{DeviceHost: want.DeviceHost, Kind: "ssh", Login: "pi", ClientSSHPubKey: "ssh-ed25519 AAAA"}

	got, err := c.MintSession(context.Background(), &cur, req)
	if err != nil || *got != want {
		t.Fatalf("MintSession = %+v, %v; want %+v", got, err, want)
	}
	// The race detector does not see the network round trip as ordering.
	mu.Lock()
	defer mu.Unlock()
	if len(keys) != 3 {
		t.Fatalf("attempts = %d, want 3 (lost answer, in flight, replay)", len(keys))
	}
	if !idempotencyKeySyntax.MatchString(keys[0]) {
		t.Fatalf("Idempotency-Key = %q, want a quoted 26-character base32 string", keys[0])
	}
	for i := 1; i < 3; i++ {
		if keys[i] != keys[0] {
			t.Fatalf("attempt %d key = %q, want the first attempt's %q", i+1, keys[i], keys[0])
		}
		// Only the proof of possession may change between attempts of one key.
		op, first := bodies[i], bodies[0]
		op.Timestamp, op.Sig, first.Timestamp, first.Sig = 0, "", 0, ""
		if op != first {
			t.Fatalf("attempt %d operation fields = %+v, want %+v", i+1, op, first)
		}
	}

	mu.Unlock()
	_, err = c.MintSession(context.Background(), &cur, req)
	mu.Lock()
	if err != nil {
		t.Fatalf("second MintSession: %v", err)
	}
	if len(keys) != 4 || keys[3] == keys[0] || !idempotencyKeySyntax.MatchString(keys[3]) {
		t.Fatalf("second call key = %q, want a new key different from %q", keys[len(keys)-1], keys[0])
	}
}

// A payload mismatch under a key is final and keeps the server's code.
func TestIdempotencyMismatchIsFinal(t *testing.T) {
	cur := credentialFor(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/user/ana")
	attempts := 0
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "SE038", "message": "key reused with a different request"})
	})
	_, err := (&Client{BaseURL: srv.URL, HTTP: srv.Client()}).MintSession(context.Background(), &cur, SessionRequest{DeviceHost: "gw", Kind: "ssh", Login: "pi", ClientSSHPubKey: "ssh-ed25519 AAAA"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnprocessableEntity || apiErr.Code != "SE038" {
		t.Fatalf("MintSession = %v, want the 422 SE038 APIError", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1: a mismatch is final", attempts)
	}
}

package identity

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A transport failure carries no error code, so it must not be read as a
// refusal: one dropped packet would end a sign-in already approved.
func TestLoginSurvivesATransportFailureMidPoll(t *testing.T) {
	var polls atomic.Int32
	var mu sync.Mutex
	var startKey string
	var pollKeys []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if strings.HasSuffix(r.URL.Path, "/device/start") {
			startKey = r.Header.Get("Idempotency-Key")
		} else {
			pollKeys = append(pollKeys, r.Header.Get("Idempotency-Key"))
		}
		mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/device/start"):
			writeJSON(t, w, map[string]any{
				"device_code": "dc", "user_code": "ABCD-EFGH",
				"verification_uri":          "https://127.0.0.1/device",
				"verification_uri_complete": "https://127.0.0.1/device?code=ABCD-EFGH",
				"interval":                  1, "expires_in": 30,
			})
		case strings.HasSuffix(r.URL.Path, "/device/token"):
			switch polls.Add(1) {
			case 1:
				// Still waiting: a normal state of the flow.
				w.WriteHeader(http.StatusPreconditionRequired)
				writeJSON(t, w, map[string]any{"code": codeAuthorizationPending, "message": "pending"})
			case 2:
				// The blip. Hijacking the connection kills it mid-request,
				// which is what a dropped packet looks like to the client.
				hj, ok := w.(http.Hijacker)
				if !ok {
					t.Error("test server cannot hijack")
					return
				}
				conn, _, err := hj.Hijack()
				if err != nil {
					t.Errorf("hijack: %v", err)
					return
				}
				conn.Close()
			default:
				leaf := selfSigned(t, "spiffe://01kpq7x2.mtls.localport.dev/user/7k2p9xq4mn3vb")
				certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
				writeJSON(t, w, map[string]any{
					"cert_pem": certPEM, "identity": "7k2p9xq4mn3vb",
					"team_id": "01kpq7x2", "team_name": "Acme Robotics",
				})
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// Built directly rather than through NewClient: that constructor enforces
	// https, and this test is about poll behaviour, not transport policy.
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	mat, err := c.Login(ctx, func(LoginPrompt) {})
	if err != nil {
		t.Fatalf("a transport blip ended the sign-in: %v", err)
	}
	if polls.Load() < 3 {
		t.Fatalf("polled %d times; the blip should have been ridden out", polls.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if !idempotencyKeySyntax.MatchString(startKey) {
		t.Fatalf("start Idempotency-Key = %q, want a quoted base32 string", startKey)
	}
	// A pending answer ends one poll, so the next carries a new key; the poll
	// lost to the blip is repeated under its own key.
	if len(pollKeys) != 3 || pollKeys[1] == pollKeys[0] || pollKeys[2] != pollKeys[1] || pollKeys[0] == startKey {
		t.Fatalf("poll keys = %q, want a new key after pending and the same key after the blip", pollKeys)
	}
	if mat.Meta.Source != SourceSSO {
		t.Fatalf("source = %q, want %q", mat.Meta.Source, SourceSSO)
	}
	if mat.Meta.TeamName != "Acme Robotics" {
		t.Fatalf("team_name = %q, want it carried from the response", mat.Meta.TeamName)
	}
	// A sign-in does not renew, and nothing may synthesize a deadline for it.
	if _, renews := mat.Meta.NextRenewal(); renews {
		t.Fatal("a sign-in must not acquire a renewal deadline")
	}
}

// A real refusal is still terminal: the poll must not loop on "denied".
func TestLoginStopsOnARealRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/device/start") {
			writeJSON(t, w, map[string]any{
				"device_code": "dc", "user_code": "ABCD-EFGH",
				"verification_uri":          "https://127.0.0.1/device",
				"verification_uri_complete": "https://127.0.0.1/device?code=ABCD-EFGH",
				"interval":                  1, "expires_in": 30,
			})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(t, w, map[string]any{"code": "SE020", "message": "not valid"})
	}))
	defer srv.Close()

	// Built directly rather than through NewClient: that constructor enforces
	// https, and this test is about poll behaviour, not transport policy.
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := c.Login(ctx, func(LoginPrompt) {}); err == nil {
		t.Fatal("a refusal must end the sign-in rather than poll to the deadline")
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, body map[string]any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Errorf("encode: %v", err)
	}
}

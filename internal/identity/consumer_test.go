package identity

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const deviceSpiffe = "spiffe://01kpq7x2.mtls.localport.dev/device/tun12345/gw-01"

func deviceCertPEM(t *testing.T) string {
	t.Helper()
	leaf := selfSigned(t, deviceSpiffe)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
}

// A setup token that yields a device certificate is refused: setup issues
// consumer credentials only.
func TestRedeemSetupTokenRefusesADeviceCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/mtls/certs" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(t, w, map[string]any{"cert_pem": deviceCertPEM(t)})
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	if _, err := c.RedeemSetupToken(context.Background(), "lps_x", 0, nil); !errors.Is(err, ErrDeviceCredential) {
		t.Fatalf("RedeemSetupToken = %v, want ErrDeviceCredential", err)
	}
}

// A sign-in that yields a device certificate is refused.
func TestLoginRefusesADeviceCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/device/start"):
			writeJSON(t, w, map[string]any{
				"device_code": "dc", "user_code": "ABCD-EFGH",
				"verification_uri": "https://dash.example/device",
				"interval":         1, "expires_in": 30,
			})
		case strings.HasSuffix(r.URL.Path, "/device/token"):
			writeJSON(t, w, map[string]any{"cert_pem": deviceCertPEM(t), "team_id": "01kpq7x2"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.Login(ctx, func(LoginPrompt) {}); !errors.Is(err, ErrDeviceCredential) {
		t.Fatalf("Login = %v, want ErrDeviceCredential", err)
	}
}

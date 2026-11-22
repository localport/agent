package identity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/localport/agent/internal/errcode"
)

// A sign-in start answer without both verification addresses is refused
// before the prompt and before any poll.
func TestLoginRefusesAStartWithoutVerificationAddresses(t *testing.T) {
	full := map[string]any{
		"device_code": "dc", "user_code": "ABCD-EFGH",
		"verification_uri":          "https://dash.example/device",
		"verification_uri_complete": "https://dash.example/device?code=ABCD-EFGH",
		"interval":                  1, "expires_in": 30,
	}
	for _, missing := range []string{"verification_uri", "verification_uri_complete"} {
		t.Run(missing, func(t *testing.T) {
			answer := map[string]any{}
			for k, v := range full {
				if k != missing {
					answer[k] = v
				}
			}
			var polled atomic.Bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/device/start") {
					writeJSON(t, w, answer)
					return
				}
				polled.Store(true)
				w.WriteHeader(http.StatusNotFound)
			}))
			defer srv.Close()
			c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			prompted := false
			_, err := c.Login(ctx, func(LoginPrompt) { prompted = true })
			var coded *errcode.Error
			if !errors.As(err, &coded) || coded.Code != errcode.ControlPlaneAnswer || prompted || polled.Load() {
				t.Fatalf("Login = %v (prompted %v, polled %v), want AG127 before the prompt", err, prompted, polled.Load())
			}
		})
	}
}

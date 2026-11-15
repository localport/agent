package identity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/localport/agent/internal/errcode"
)

// A server that echoes the request's secret must not put it into any
// rendering of the error, while the typed refusal stays matchable.
func TestServerEchoOfTheSecretIsRedactedAtTheSource(t *testing.T) {
	const setupToken = "lps_setup_0123456789abcdef"
	const joinToken = "4815162342"
	cases := []struct {
		name string
		call func(c *Client) error
		// answer is the server's response; %s is the echoed secret.
		status int
		answer string
		secret string
	}{
		{
			name: "setup token echoed in a refusal",
			call: func(c *Client) error {
				_, err := c.RedeemSetupToken(context.Background(), setupToken, 0, nil)
				return err
			},
			status: http.StatusForbidden,
			answer: `{"code":"SE010 %[1]s","message":"token %[1]s is not valid"}`,
			secret: setupToken,
		},
		{
			name:   "join token echoed in a refusal",
			call:   func(c *Client) error { _, err := c.EnrolDevice(context.Background(), joinToken, 0, nil); return err },
			status: http.StatusForbidden,
			answer: `{"code":"SE011","message":"join token %s is spent"}`,
			secret: joinToken,
		},
		{
			name:   "join token echoed as the device host",
			call:   func(c *Client) error { _, err := c.EnrolDevice(context.Background(), joinToken, 0, nil); return err },
			status: http.StatusOK,
			answer: `{"cert_pem":"PEM","device_host":"%s_"}`,
			secret: joinToken,
		},
		{
			name:   "join token echoed as the region",
			call:   func(c *Client) error { _, err := c.EnrolDevice(context.Background(), joinToken, 0, nil); return err },
			status: http.StatusOK,
			answer: `{"cert_pem":"PEM","region":"%s_"}`,
			secret: joinToken,
		},
		{
			// encoding/json quotes a number that overflows its field, so
			// any numeric answer field can echo a secret; this case pins
			// the redaction for that path.
			name: "secret echoed in a malformed answer",
			call: func(c *Client) error {
				var out struct {
					N int8 `json:"n"`
				}
				return c.post(context.Background(), "/v1/devices/enrol", "", "", map[string]string{}, &out, joinToken)
			},
			status: http.StatusOK,
			answer: `{"n": %s}`,
			secret: joinToken,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprintf(w, tc.answer, tc.secret)
			})
			err := tc.call(&Client{BaseURL: srv.URL, HTTP: srv.Client()})
			if err == nil {
				t.Fatal("the call succeeded; want the refusal or parse failure")
			}
			rendered, _ := errcode.Render(err)
			for name, text := range map[string]string{"Error()": err.Error(), "%+v": fmt.Sprintf("%+v", err), "Render": rendered} {
				if strings.Contains(text, tc.secret) {
					t.Errorf("%s = %q holds the secret", name, text)
				}
			}
			var apiErr *APIError
			if tc.status != http.StatusOK && (!errors.As(err, &apiErr) || apiErr.Status != tc.status) {
				t.Fatalf("err = %v, want the %d APIError", err, tc.status)
			}
		})
	}
}

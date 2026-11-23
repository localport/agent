package identity

import (
	"errors"
	"testing"

	"github.com/localport/agent/internal/errcode"
)

// Sign-in addresses must be https on the API's registrable domain; the user
// code reaches the terminal without control characters.
func TestLoginPromptRefusesForeignOrUnsafeAddresses(t *testing.T) {
	c := &Client{BaseURL: "https://api.localport.io"}
	start := func(uri, complete string) deviceStartResponse {
		return deviceStartResponse{UserCode: "ABCD-EFGH", VerificationURI: uri, VerificationURIComplete: complete}
	}
	ok := "https://dashboard.localport.io/device"
	p, err := c.loginPrompt(start(ok, ok+"?code=ABCD-EFGH"))
	if err != nil || p.VerificationURI != ok {
		t.Fatalf("dashboard on the API's domain: %+v, %v", p, err)
	}
	for _, bad := range []string{
		"http://dashboard.localport.io/device",
		"https://evil.example/device",
		"https://localport.io.evil.example/device",
		"https://evillocalport.io/device",
		"https://user@dashboard.localport.io/device",
		"https://dashboard.localport.io/device" + string(rune(0x202e)),
		"https://dashboard.localport.io/\x1b]8;;https://evil.example\x07x",
	} {
		for _, s := range []deviceStartResponse{start(bad, ok), start(ok, bad)} {
			var coded *errcode.Error
			if _, err := c.loginPrompt(s); !errors.As(err, &coded) || coded.Code != errcode.ControlPlaneAnswer {
				t.Errorf("%q: err %v, want ControlPlaneAnswer", bad, err)
			}
		}
	}
	s := start(ok, ok)
	s.UserCode = "AB\x1b[2JCD"
	if p, err := c.loginPrompt(s); err != nil || p.UserCode != "AB[2JCD" {
		t.Errorf("user code %q, %v; want control characters removed", p.UserCode, err)
	}
	ip := &Client{BaseURL: "https://10.0.0.1"}
	if _, err := ip.loginPrompt(start("https://20.0.0.1/device", "https://20.0.0.1/device")); err == nil {
		t.Error("an IP API accepted another IP's address")
	}
}

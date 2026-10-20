package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

// A device Register carries no token, since the TLS client certificate
// authenticates it, and reports what the device enabled locally.
func TestDeviceRegisterOmitsTheTokenAndCarriesCapabilities(t *testing.T) {
	raw, err := json.Marshal(&RegisterPayload{
		Kind:         KindDevice,
		Capabilities: []string{"terminal", "desktop"},
		Logins:       []string{"pi"},
		Desktop:      []string{"rdp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if strings.Contains(s, `"token"`) {
		t.Errorf("device Register sends a token: %s", s)
	}
	for _, want := range []string{`"capabilities":["terminal","desktop"]`, `"logins":["pi"]`, `"desktop":["rdp"]`} {
		if !strings.Contains(s, want) {
			t.Errorf("Register %s lacks %s", s, want)
		}
	}
	bind, _ := json.Marshal(&MuxBindPayload{SessionID: "s"})
	if strings.Contains(string(bind), `"token"`) {
		t.Errorf("device MuxBind sends a token: %s", bind)
	}
}

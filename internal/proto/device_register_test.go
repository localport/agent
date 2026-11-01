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
		SessionAuth:  "no_pam",
		RunAsAgent:   true,
		// FullDiskAccess left empty, as off macOS.
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if strings.Contains(s, `"token"`) {
		t.Errorf("device Register sends a token: %s", s)
	}
	for _, want := range []string{`"capabilities":["terminal","desktop"]`, `"logins":["pi"]`, `"desktop":["rdp"]`,
		`"session_auth":"no_pam"`, `"run_as_agent":true`} {
		if !strings.Contains(s, want) {
			t.Errorf("Register %s lacks %s", s, want)
		}
	}
	if strings.Contains(s, `"full_disk_access"`) {
		t.Errorf("Register %s carries full_disk_access off macOS", s)
	}
	mac, _ := json.Marshal(&RegisterPayload{Kind: KindDevice, SessionAuth: "pam", FullDiskAccess: "denied"})
	if !strings.Contains(string(mac), `"full_disk_access":"denied"`) || strings.Contains(string(mac), `"run_as_agent"`) {
		t.Errorf("macOS Register %s", mac)
	}
	bind, _ := json.Marshal(&MuxBindPayload{SessionID: "s"})
	if strings.Contains(string(bind), `"token"`) {
		t.Errorf("device MuxBind sends a token: %s", bind)
	}
}

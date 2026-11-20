//go:build linux || darwin

package launcher

import (
	"bytes"
	"testing"

	"github.com/localport/agent/internal/config"
)

// The client address reaches the helper through authorize and the helper
// wire; the helper refuses an invalid one.
func TestClientAddrReachesTheHelper(t *testing.T) {
	load := testConfig(t, config.LocalDevice{Enable: []config.Capability{config.CapabilityTerminal}, Logins: []string{"pi"}})
	req := terminalRequest("pi")
	req.V, req.ClientAddr = Version, "[2001:db8::7]:5022"
	h, err := authorize(load, "", req, FullDiskAccessDenied)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteHelperRequest(&buf, h); err != nil {
		t.Fatal(err)
	}
	got, err := ReadHelperRequest(&buf)
	if err != nil || got.ClientAddr != req.ClientAddr || got.FullDiskAccess != FullDiskAccessDenied {
		t.Fatalf("helper read %+v, %v", got, err)
	}
	for _, bad := range []HelperRequest{
		{Kind: KindTerminal, Login: "pi", FullDiskAccess: "maybe"},
		{Kind: KindForward, Login: "pi", FullDiskAccess: FullDiskAccessGranted},
	} {
		buf.Reset()
		if err := WriteHelperRequest(&buf, bad); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadHelperRequest(&buf); err == nil {
			t.Errorf("the helper read %+v", bad)
		}
	}
	buf.Reset()
	if err := WriteHelperRequest(&buf, HelperRequest{Kind: KindTerminal, Login: "pi", ClientAddr: "[fe80::1%eth0]:22"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadHelperRequest(&buf); err == nil {
		t.Fatal("the helper read a client address with a zone")
	}
}

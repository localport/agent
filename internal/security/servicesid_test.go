package security

import "testing"

// TrustedInstaller's service SID is published by Microsoft and shows the
// derivation matches the one Windows uses.
func TestServiceSIDMatchesWindows(t *testing.T) {
	const want = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	if got := ServiceSID("TrustedInstaller"); got != want {
		t.Fatalf("ServiceSID(TrustedInstaller) = %s, want %s", got, want)
	}
	if ServiceSID("localport-device") != ServiceSID("LOCALPORT-DEVICE") {
		t.Fatal("the service SID must not depend on the name's case")
	}
}

//go:build windows

package launcher

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

// The status client trusts a pipe only when its owner is SYSTEM or
// Administrators and every allow entry names one of them.
func TestCheckStatusPipe(t *testing.T) {
	for _, c := range []struct {
		name, sddl string
		ok         bool
	}{
		{"the launcher's descriptor", "O:SYD:P(A;;GA;;;SY)(A;;0x120081;;;BA)", true},
		{"administrators owner", "O:BAD:P(A;;GA;;;SY)(A;;0x120081;;;BA)", true},
		{"owned by a user", "O:S-1-5-21-1-2-3-1001D:P(A;;GA;;;SY)", false},
		{"grants everyone", "O:SYD:P(A;;GA;;;SY)(A;;0x120081;;;WD)", false},
		{"grants a user", "O:SYD:P(A;;GA;;;SY)(A;;0x120081;;;S-1-5-21-1-2-3-1001)", false},
		{"no DACL", "O:SY", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(c.sddl)
			if err != nil {
				t.Fatal(err)
			}
			err = checkStatusPipe(sd)
			if c.ok && err != nil {
				t.Fatalf("checkStatusPipe = %v, want nil", err)
			}
			if !c.ok && !errors.Is(err, ErrStatusUntrusted) {
				t.Fatalf("checkStatusPipe = %v, want ErrStatusUntrusted", err)
			}
		})
	}
}

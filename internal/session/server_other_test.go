//go:build !linux && !darwin

package session

import "testing"

// A build without the ticket's kind refuses it kind_unavailable, unspent,
// after every other check passed.
func TestServeRefusesAKindThisBuildLacks(t *testing.T) {
	ts := newTestServer(t, nil)
	if got := ts.refusal(t, ts.ticket(t, nil)); got != CodeKindUnavailable {
		t.Fatalf("refused %q, want kind_unavailable", got)
	}
	if ts.spent(ts.f.payload().JTI) {
		t.Fatal("kind_unavailable spent the ticket")
	}
}

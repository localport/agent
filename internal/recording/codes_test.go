package recording

import (
	"net/http"
	"testing"
)

// The statuses are the HTTP statuses the edge answers for each recording
// error code.
func TestStatus(t *testing.T) {
	want := map[string]int{
		"recording_not_found":     http.StatusNotFound,
		"recording_bad_request":   http.StatusBadRequest,
		"recording_proof_invalid": http.StatusUnauthorized,
		"recording_conflict":      http.StatusConflict,
		"recording_out_of_order":  http.StatusConflict,
		"recording_mismatch":      http.StatusConflict,
		"recording_closed":        http.StatusGone,
		"recording_limit":         http.StatusRequestEntityTooLarge,
		"recording_quota":         http.StatusTooManyRequests,
		"recording_busy":          http.StatusServiceUnavailable,
		"recording_storage":       http.StatusBadGateway,
		"recording_unavailable":   http.StatusServiceUnavailable,
	}
	if len(statusByCode) != len(want) {
		t.Fatalf("statusByCode has %d codes, want %d", len(statusByCode), len(want))
	}
	for code, status := range want {
		got, ok := Status(code)
		if !ok || got != status {
			t.Errorf("Status(%q) = %d, %v; want %d, true", code, got, ok, status)
		}
	}
	if _, ok := Status("recording_unknown"); ok {
		t.Error("Status accepted an unknown code")
	}
}

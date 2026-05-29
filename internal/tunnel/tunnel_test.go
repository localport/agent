package tunnel

import (
	"strings"
	"testing"

	"github.com/localport/agent/internal/proto"
)

func TestAllowedRedirectHost(t *testing.T) {
	allow := []string{
		"connect.eu.localport.dev:443",
		"connect.us.localport.dev:443",
		"new-region.localport.dev:443",
		"localport.dev:443",
		"CONNECT.EU.LOCALPORT.DEV:443",  // case-insensitive
		"connect.eu.localport.dev.:443", // trailing dot FQDN
	}
	for _, a := range allow {
		if !allowedRedirectHost(a) {
			t.Errorf("expected %q to be allowed", a)
		}
	}
	deny := []string{
		"evil.com:443",
		"localport.dev.evil.com:443",
		"notlocalport.dev:443",
		"localhost:443",
		"127.0.0.1:443",
		"localport.dev.attacker.io:443",
		"",
	}
	for _, d := range deny {
		if allowedRedirectHost(d) {
			t.Errorf("expected %q to be refused", d)
		}
	}
}

func TestRegistrationErrorHidesCode(t *testing.T) {
	err := &RegistrationError{
		Message: "authentication token is invalid",
		Code:    "TK003",
	}
	if err.Code != "TK003" {
		t.Fatalf("Code field should be retained, got %q", err.Code)
	}
	if strings.Contains(err.Error(), "TK003") {
		t.Fatalf("Error() leaks the opaque code: %q", err.Error())
	}
	if err.Error() != "authentication token is invalid" {
		t.Fatalf("Error() = %q, want the bare sanitized message", err.Error())
	}
}

func TestRegistrationErrorRetryableDefaultsTrue(t *testing.T) {
	err := registrationErrorFrom(&proto.RegisterAckPayload{
		Success:   false,
		Error:     "rejected",
		ErrorCode: "TK003",
	})
	if !err.Retryable {
		t.Fatal("retryable should default to true when the field is unset")
	}
	if err.Code != "TK003" {
		t.Fatalf("Code = %q", err.Code)
	}
}

func TestRegistrationErrorRetryableExplicit(t *testing.T) {
	retryable := false
	err := registrationErrorFrom(&proto.RegisterAckPayload{
		Success:   false,
		Error:     "limit reached",
		ErrorCode: "BL007",
		Retryable: &retryable,
		LimitType: proto.LimitBandwidth,
	})
	if err.Retryable {
		t.Fatal("retryable should be false")
	}
	if err.LimitType != proto.LimitBandwidth {
		t.Fatalf("LimitType = %q", err.LimitType)
	}
}

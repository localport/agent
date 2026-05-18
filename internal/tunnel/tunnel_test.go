package tunnel

import (
	"testing"

	"github.com/localport/agent/internal/proto"
)

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

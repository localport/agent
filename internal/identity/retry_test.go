package identity

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
)

// A 4xx that is not 429 must never be retried: it is a refusal, and repeating
// it only spends request quota.
func TestRetryClassification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil is not an error", nil, false},
		{"dial failure", errors.New("dial tcp: connection refused"), true},
		{"unexpected EOF", io.ErrUnexpectedEOF, true},
		{"500", &APIError{Status: http.StatusInternalServerError}, true},
		{"502", &APIError{Status: http.StatusBadGateway}, true},
		{"503", &APIError{Status: http.StatusServiceUnavailable}, true},
		{"429 is the one retryable 4xx", &APIError{Status: http.StatusTooManyRequests}, true},
		{"400 is terminal", &APIError{Status: http.StatusBadRequest}, false},
		{"401 is terminal", &APIError{Status: http.StatusUnauthorized}, false},
		{"403 is terminal", &APIError{Status: http.StatusForbidden}, false},
		{"404 is terminal", &APIError{Status: http.StatusNotFound}, false},
		{"409 is terminal", &APIError{Status: http.StatusConflict}, false},
		{"context cancelled is not retryable", context.Canceled, false},
		{"deadline exceeded is not retryable", context.DeadlineExceeded, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRetryable(tc.err); got != tc.want {
				t.Fatalf("isRetryable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// Wrapping must not change the verdict: every call site wraps with context.
func TestRetryClassificationSeesThroughWrapping(t *testing.T) {
	wrapped := errors.Join(errors.New("while renewing"), &APIError{Status: http.StatusForbidden})
	if isRetryable(wrapped) {
		t.Fatal("a wrapped 403 must stay terminal")
	}
}

// A budget of zero is what CI asks for with --wait 0.
func TestZeroBudgetMakesExactlyOneAttempt(t *testing.T) {
	attempts := 0
	err := retry(context.Background(), 0, nil, func() error {
		attempts++
		return errors.New("unreachable")
	})
	if err == nil {
		t.Fatal("want the transport error back")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want exactly 1", attempts)
	}
}

// A terminal error must not consume the budget, whatever --wait says.
func TestTerminalErrorIgnoresTheBudget(t *testing.T) {
	attempts := 0
	start := time.Now()
	err := retry(context.Background(), time.Hour, nil, func() error {
		attempts++
		return &APIError{Status: http.StatusForbidden, Message: "spent"}
	})
	if err == nil {
		t.Fatal("want the refusal back")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1: a refused token must fail immediately, not sit for an hour", attempts)
	}
	if time.Since(start) > time.Second {
		t.Fatal("a terminal error waited; --wait must apply only to retryable conditions")
	}
}

func TestRetrySucceedsAfterATransientFailure(t *testing.T) {
	attempts := 0
	err := retry(context.Background(), 30*time.Second, nil, func() error {
		attempts++
		if attempts < 2 {
			return errors.New("connection reset")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

// Cancellation must win over a pending wait, so Ctrl-C is honoured.
func TestRetryStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()

	err := retry(ctx, time.Hour, nil, func() error { return errors.New("unreachable") })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// Jitter must actually vary and stay inside the bound.
func TestJitterIsBoundedAndVaries(t *testing.T) {
	const d = time.Second
	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		got := jitter(d)
		if got < 0 || got > d {
			t.Fatalf("jitter(%s) = %s, outside [0, %s]", d, got, d)
		}
		seen[got] = true
	}
	if len(seen) < 50 {
		t.Fatalf("jitter produced %d distinct values in 200 draws", len(seen))
	}
	if jitter(0) != 0 {
		t.Fatal("jitter(0) must be 0")
	}
}

func TestParseRetryAfter(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"5", 5 * time.Second},
		{"0", 0},
		{"-3", 0},
		{"nonsense", 0},
	}
	for _, tc := range cases {
		if got := parseRetryAfter(tc.in); got != tc.want {
			t.Fatalf("parseRetryAfter(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
	// An HTTP-date in the future resolves to a positive delay; one in the past
	// resolves to zero so a stale header cannot park the agent.
	if got := parseRetryAfter(time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)); got <= 0 {
		t.Fatalf("a future HTTP-date must yield a positive delay, got %s", got)
	}
	if got := parseRetryAfter(time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)); got != 0 {
		t.Fatalf("a past HTTP-date must yield 0, got %s", got)
	}
}

// A hostile or misconfigured server must not be able to park the agent past the
// budget it was given.
func TestRetryAfterIsClampedToTheBudget(t *testing.T) {
	attempts := 0
	start := time.Now()
	err := retry(context.Background(), 2*time.Second, nil, func() error {
		attempts++
		return &APIError{Status: http.StatusTooManyRequests, retryAfter: 24 * time.Hour}
	})
	if err == nil {
		t.Fatal("want the 429 back once the budget is spent")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1: a Retry-After beyond the budget ends the attempt", attempts)
	}
	if time.Since(start) > time.Second {
		t.Fatal("the agent waited on an out-of-budget Retry-After")
	}
}

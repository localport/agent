package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"
)

// Probe walks dialers in priority order. The first one whose TLS
// handshake plus ALPN negotiation succeeds within the per-attempt budget
// wins; the caller caches that dialer and reuses it for data dial-backs
// in the same session.
//
// Probing is single-attempt. Callers that need retries should drive
// them from a reconnect loop.
func Probe(
	ctx context.Context,
	edgeAddr string,
	budget time.Duration,
	dialers []Dialer,
	logger *slog.Logger,
) (net.Conn, Dialer, error) {
	if len(dialers) == 0 {
		return nil, nil, errors.New("probe: no dialers configured")
	}
	if budget <= 0 {
		budget = 2 * time.Second
	}

	host, port := SplitHostPort(edgeAddr)
	var attempts []string

	for _, d := range dialers {
		attemptCtx, cancel := context.WithTimeout(ctx, budget)
		conn, err := d.Dial(attemptCtx, host, port)
		cancel()

		if err == nil {
			if logger != nil {
				logger.Debug("transport probe succeeded",
					slog.String("transport", d.Kind().String()),
					slog.String("edge", net.JoinHostPort(host, port)))
			}
			return conn, d, nil
		}

		attempts = append(attempts, fmt.Sprintf("%s=%v", d.Kind(), err))
		if logger != nil {
			logger.Debug("transport probe failed",
				slog.String("transport", d.Kind().String()),
				slog.String("edge", net.JoinHostPort(host, port)),
				slog.Any("error", err))
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, nil, fmt.Errorf("%w (tried: %s)", ErrNoTransport, strings.Join(attempts, "; "))
}

// DefaultDialers returns the priority-ordered set of dialers: raw first
// (lowest overhead), then ws (firewall-tolerant fallback).
func DefaultDialers(opts Options) []Dialer {
	timeout := opts.DialTimeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	return []Dialer{
		&RawDialer{DialTimeout: timeout},
		&WSDialer{DialTimeout: timeout, Path: opts.WSPath},
	}
}

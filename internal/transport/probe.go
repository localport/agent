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
	var tried []string
	var failures []error

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

		tried = append(tried, d.Kind().String())
		failures = append(failures, fmt.Errorf("%s: %w", d.Kind(), err))
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
	// The dial errors carry addresses and TLS text, so they are the cause
	// (--verbose and logs), and the user text names only the kinds tried.
	return nil, nil, ErrNoTransport.With(errors.Join(failures...), "tried "+strings.Join(tried, ", "))
}

// DefaultDialers returns the priority-ordered set of dialers: raw first
// (lowest overhead), then ws (firewall-tolerant fallback).
func DefaultDialers(opts Options) []Dialer {
	timeout := opts.DialTimeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	return []Dialer{
		&RawDialer{DialTimeout: timeout, ServerName: opts.ServerName, ClientCert: opts.ClientCert},
		&WSDialer{DialTimeout: timeout, Path: opts.WSPath, ServerName: opts.ServerName, ClientCert: opts.ClientCert},
	}
}

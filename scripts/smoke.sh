#!/usr/bin/env bash
set -euo pipefail

echo "[smoke] build"
go build ./cmd/localport

echo "[smoke] help / version"
go run ./cmd/localport --help >/dev/null
go run ./cmd/localport version >/dev/null

echo "[smoke] tunnel command rejects bad invocation"
if go run ./cmd/localport tunnel --token tok_test >/dev/null 2>&1; then
  echo "expected tunnel to fail without --local" >&2
  exit 1
fi

echo "[smoke] access command rejects bad invocation"
if go run ./cmd/localport access >/dev/null 2>&1; then
  echo "expected access to fail without a remote" >&2
  exit 1
fi

echo "[smoke] done"

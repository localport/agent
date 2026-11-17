#!/usr/bin/env bash
set -euo pipefail

echo "[smoke] build"
go build -o /dev/null ./cmd/localport

echo "[smoke] help / version"
go run ./cmd/localport --help >/dev/null
go run ./cmd/localport version >/dev/null

echo "[smoke] flat tunnel form rejects a missing --local"
if go run ./cmd/localport --token tok_test >/dev/null 2>&1; then
  echo "expected the flat form to fail without --local" >&2
  exit 1
fi

echo "[smoke] up --config rejects a missing file"
if env -u LOCALPORT_TOKEN go run ./cmd/localport up --config /nonexistent/localport.yaml >/dev/null 2>&1; then
  echo "expected up --config to fail without its file" >&2
  exit 1
fi

echo "[smoke] access command rejects bad invocation"
if go run ./cmd/localport access >/dev/null 2>&1; then
  echo "expected access to fail without a remote" >&2
  exit 1
fi

echo "[smoke] done"

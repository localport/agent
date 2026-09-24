#!/usr/bin/env bash
# Verifies checksums.txt.sig against release/allowed_signers, then every file
# listed in checksums.txt.
#
#   scripts/release/verify.sh <dir>
#
# Needs OpenSSH 8.1 or later.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
signers="$root/release/allowed_signers"
dir="${1:?usage: verify.sh <dir>}"

readonly identity="release@localport.io"
readonly namespace="localport-release"

[ -s "$signers" ] || { echo "error: $signers is missing or empty" >&2; exit 1; }
[ -f "$dir/checksums.txt" ] || { echo "error: $dir/checksums.txt not found" >&2; exit 1; }
[ -f "$dir/checksums.txt.sig" ] || { echo "error: $dir/checksums.txt.sig not found" >&2; exit 1; }

ssh-keygen -Y verify \
	-f "$signers" \
	-I "$identity" \
	-n "$namespace" \
	-s "$dir/checksums.txt.sig" \
	<"$dir/checksums.txt"

cd "$dir"
if command -v sha256sum >/dev/null 2>&1; then
	sha256sum --check --strict checksums.txt
else
	shasum -a 256 --check --strict checksums.txt
fi

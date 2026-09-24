#!/usr/bin/env bash
# Writes checksums.txt for every file in a release directory.
#
#   scripts/release/checksums.sh <dir>
#
# Format: "<sha256>  <name>", sorted by name, as written by sha256sum.
set -euo pipefail

dir="${1:?usage: checksums.sh <dir>}"
cd "$dir"

if command -v sha256sum >/dev/null 2>&1; then
	hash=(sha256sum)
else
	hash=(shasum -a 256)
fi

find . -maxdepth 1 -type f ! -name 'checksums.txt*' -print |
	sed 's|^\./||' |
	LC_ALL=C sort |
	while IFS= read -r f; do "${hash[@]}" "$f"; done >checksums.txt

echo "wrote $dir/checksums.txt ($(wc -l <checksums.txt | tr -d ' ') files)"

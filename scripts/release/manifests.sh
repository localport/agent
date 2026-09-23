#!/usr/bin/env bash
# Opens pull requests that update the Homebrew formula and the Scoop manifest
# to a published release.
#
#   scripts/release/manifests.sh <dist-dir>
#
# Environment:
#   VERSION    release tag, vX.Y.Z
#   GH_TOKEN   a token that may create branches and pull requests on
#              localport/homebrew-tap and localport/scoop-bucket
#
# Hashes come from <dist-dir>/checksums.txt, already verified by the caller.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
dist="$(cd "${1:?usage: manifests.sh <dist-dir>}" && pwd)"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

: "${VERSION:?VERSION is required (vX.Y.Z)}"
: "${GH_TOKEN:?GH_TOKEN is required}"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "manifests track stable releases only; $VERSION is not vX.Y.Z"
version="${VERSION#v}"

sum() {
	local s
	s="$(awk -v n="$1" '$2 == n { print $1 }' "$dist/checksums.txt")"
	[[ "$s" =~ ^[0-9a-f]{64}$ ]] || die "no checksum for $1"
	printf '%s' "$s"
}

render() {
	sed -e "s|@VERSION@|$version|g" \
		-e "s|@SHA256_DARWIN_ARM64@|$(sum localport-darwin-arm64)|" \
		-e "s|@SHA256_DARWIN_AMD64@|$(sum localport-darwin-amd64)|" \
		-e "s|@SHA256_LINUX_ARM64@|$(sum localport-linux-arm64)|" \
		-e "s|@SHA256_LINUX_AMD64@|$(sum localport-linux-amd64)|" \
		-e "s|@SHA256_WINDOWS_AMD64@|$(sum localport-windows-amd64.exe)|" \
		"$1"
}

# propose <repo> <path> <rendered file>
propose() {
	local repo="$1" path="$2" file="$3" branch="localport-$version"
	local base base_sha current_sha

	base="$(gh api "repos/$repo" --jq .default_branch)"
	current_sha="$(gh api "repos/$repo/contents/$path?ref=$base" --jq .sha 2>/dev/null || true)"
	if [ -n "$current_sha" ] &&
		gh api "repos/$repo/contents/$path?ref=$base" --jq .content | base64 -d | cmp -s - "$file"; then
		echo "    $repo: $path already at $version"
		return
	fi

	if [ -n "$(gh pr list --repo "$repo" --head "$branch" --state open --json number --jq '.[].number')" ]; then
		echo "    $repo: pull request for $version already open"
		return
	fi

	# Reset a branch left by a failed run.
	base_sha="$(gh api "repos/$repo/git/ref/heads/$base" --jq .object.sha)"
	if gh api "repos/$repo/git/ref/heads/$branch" >/dev/null 2>&1; then
		gh api -X PATCH "repos/$repo/git/refs/heads/$branch" -f sha="$base_sha" -F force=true >/dev/null
	else
		gh api "repos/$repo/git/refs" -f ref="refs/heads/$branch" -f sha="$base_sha" >/dev/null
	fi
	local args=(-X PUT "repos/$repo/contents/$path"
		-f message="localport $version"
		-f content="$(base64 <"$file" | tr -d '\n')"
		-f branch="$branch")
	[ -n "$current_sha" ] && args+=(-f sha="$current_sha")
	gh api "${args[@]}" >/dev/null

	gh pr create --repo "$repo" --base "$base" --head "$branch" \
		--title "localport $version" \
		--body "Updates localport to [$VERSION](https://github.com/localport/agent/releases/tag/$VERSION). Hashes are taken from the release's signed checksums.txt." >/dev/null
	echo "    $repo: pull request opened for $version"
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

render "$root/packaging/homebrew/localport.rb.in" >"$work/localport.rb"
render "$root/packaging/scoop/localport.json.in" >"$work/localport.json"

echo ">>> package manager manifests"
propose localport/homebrew-tap Formula/localport.rb "$work/localport.rb"
propose localport/scoop-bucket bucket/localport.json "$work/localport.json"

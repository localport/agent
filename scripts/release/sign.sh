#!/usr/bin/env bash
# Signs a draft release. Maintainer only.
#
#   make release-sign TAG=vX.Y.Z
#
# 1. Downloads the draft's assets.
# 2. Checks each one's build provenance against the release workflow and the
#    tag, and each binary's hash against checksums.txt.
# 3. Signs checksums.txt with the release key held by ssh-agent.
# 4. Verifies the new signature and uploads it to the draft.
#
# The release key (release/signing-key.pub) must be loaded in the ssh-agent at
# SSH_AUTH_SOCK. See RELEASING.md.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
readonly repo="localport/agent"
readonly workflow="$repo/.github/workflows/release.yml"
readonly namespace="localport-release"
tag="${1:?usage: sign.sh vX.Y.Z}"
pubkey="$root/release/signing-key.pub"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

case "$tag" in
v[0-9]*) ;;
*) die "tag must look like vX.Y.Z, got $tag" ;;
esac
for tool in gh ssh-keygen; do
	command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done
[ -s "$pubkey" ] || die "$pubkey is missing; see RELEASING.md"
ssh-add -L 2>/dev/null | grep -qF "$(cut -d' ' -f2 "$pubkey")" ||
	die "the release key is not in ssh-agent (SSH_AUTH_SOCK=${SSH_AUTH_SOCK:-unset})"

[ "$(gh release view "$tag" --repo "$repo" --json isDraft --jq .isDraft)" = true ] ||
	die "$tag is not a draft release; a published release is never re-signed here"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo ">>> downloading $tag"
gh release download "$tag" --repo "$repo" --dir "$work"
rm -f "$work/checksums.txt.sig"

echo ">>> verifying build provenance"
while read -r _ name; do
	gh attestation verify "$work/$name" \
		--repo "$repo" \
		--signer-workflow "$workflow" \
		--source-ref "refs/tags/$tag" \
		--deny-self-hosted-runners >/dev/null ||
		die "provenance check failed for $name"
	echo "    $name"
done <"$work/checksums.txt"
gh attestation verify "$work/checksums.txt" \
	--repo "$repo" \
	--signer-workflow "$workflow" \
	--source-ref "refs/tags/$tag" \
	--deny-self-hosted-runners >/dev/null ||
	die "provenance check failed for checksums.txt"

echo ">>> verifying checksums"
(cd "$work" && shasum -a 256 --check --strict --quiet checksums.txt) ||
	die "a file does not match checksums.txt"

echo ">>> signing checksums.txt (confirm on the key)"
ssh-keygen -Y sign -f "$pubkey" -n "$namespace" "$work/checksums.txt"

"$root/scripts/release/verify.sh" "$work" >/dev/null ||
	die "the new signature does not verify against release/allowed_signers"

gh release upload "$tag" "$work/checksums.txt.sig" --repo "$repo" --clobber
echo ">>> uploaded checksums.txt.sig to $tag"
echo "    next: approve the publish job for $tag in GitHub Actions"

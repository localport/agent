#!/usr/bin/env bash
# Runs the release pipeline with throwaway keys. Publishes nothing.
#
#   make release-dryrun
#
# Needs Docker, nfpm, gpg and openssl.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

for tool in docker nfpm gpg openssl; do
	command -v "$tool" >/dev/null 2>&1 || { echo "error: $tool is required" >&2; exit 1; }
done

keys="$(mktemp -d "${TMPDIR:-/tmp}/lp-keys.XXXXXX")"
GNUPGHOME="$keys/gnupg"
export GNUPGHOME
cleanup() {
	gpgconf --kill gpg-agent >/dev/null 2>&1 || true
	rm -rf "$keys" dist/dryrun-keys
}
trap cleanup EXIT
mkdir -m 700 "$GNUPGHOME"

echo ">>> throwaway keys"
gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
	--quick-gen-key 'Localport dry run <dryrun@localport.invalid>' rsa4096 sign 1d
gpg --batch --armor --pinentry-mode loopback --passphrase '' --export-secret-keys >"$keys/repo.asc"
openssl genrsa -out "$keys/apk.rsa" 4096 2>/dev/null

version="v0.0.0"
make dist VERSION="$version"

# Inside the tree, where the repository containers can read them.
pub="dist/dryrun-keys"
rm -rf "$pub"
mkdir -p "$pub"
gpg --batch --export >"$pub/localport-archive-keyring.gpg"
gpg --batch --armor --export >"$pub/RPM-GPG-KEY-localport"
openssl rsa -in "$keys/apk.rsa" -pubout -out "$pub/localport-dryrun.rsa.pub" 2>/dev/null
date -u +%Y.%m.%d >"$pub/VERSION"

VERSION="$version" RPM_KEY_FILE="$keys/repo.asc" APK_KEY_FILE="$keys/apk.rsa" KEYS_DIR="$pub" \
	make packages
make repo REPO_GPG_KEY_FILE="$keys/repo.asc"
KEYS_DIR="$pub" make repo-apk APK_KEY_FILE="$keys/apk.rsa"
scripts/release/repo-test.sh dist/repo "$pub"

echo ">>> container image"
image="localport-dryrun:$$"
docker buildx build --quiet --load -f packaging/Dockerfile -t "$image" dist >/dev/null
docker run --rm "$image" version
docker rmi "$image" >/dev/null

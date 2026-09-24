#!/usr/bin/env bash
# Builds the signed Linux packages for a release.
#
#   scripts/release/packages.sh <dist-dir> <out-dir>
#
# Environment:
#   VERSION          release tag, vX.Y.Z (stable releases only)
#   RPM_KEY_FILE     OpenPGP private key that signs rpm packages
#   APK_KEY_FILE     RSA private key (PEM) that signs apk packages
#   KEYS_DIR         public keys, default release/keys
#   NFPM_RPM_PASSPHRASE  the rpm key's passphrase, when it has one
#
# Output:
#   <out>/deb/*.deb             amd64, arm64, armhf, plus the keyring (all)
#   <out>/rpm/*.rpm             x86_64, aarch64, plus the keyring (noarch)
#   <out>/apk/<arch>/*.apk      x86_64, aarch64, armhf, armv7
#
# The linux/arm binary backs both armhf and armv7. There is no 32-bit ARM rpm.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
dist="$(cd "${1:?usage: packages.sh <dist-dir> <out-dir>}" && pwd)"
out="${2:?usage: packages.sh <dist-dir> <out-dir>}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

: "${VERSION:?VERSION is required (vX.Y.Z)}"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
	die "package repositories carry stable releases only; $VERSION is not vX.Y.Z"
[ -s "${RPM_KEY_FILE:-}" ] || die "RPM_KEY_FILE must name the rpm signing key"
[ -s "${APK_KEY_FILE:-}" ] || die "APK_KEY_FILE must name the apk signing key"
command -v nfpm >/dev/null 2>&1 || die "nfpm is required"

export KEYS_DIR="${KEYS_DIR:-$root/release/keys}"
KEYS_DIR="$(cd "$KEYS_DIR" && pwd)"
for f in localport-archive-keyring.gpg RPM-GPG-KEY-localport VERSION; do
	[ -s "$KEYS_DIR/$f" ] || die "$KEYS_DIR/$f is missing"
done
shopt -s nullglob
apk_pubs=("$KEYS_DIR"/*.rsa.pub)
shopt -u nullglob
[ "${#apk_pubs[@]}" -eq 1 ] || die "$KEYS_DIR must hold exactly one *.rsa.pub"

export PKG_VERSION="${VERSION#v}"
export KEYRING_VERSION
KEYRING_VERSION="$(tr -d '[:space:]' <"$KEYS_DIR/VERSION")"
export APK_KEY_NAME
APK_KEY_NAME="$(basename "${apk_pubs[0]}" .rsa.pub)"
export RPM_KEY_FILE APK_KEY_FILE
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}"

# nfpm resolves relative sources against the working directory.
cd "$root"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
sed "s|@APK_KEY_NAME@|$APK_KEY_NAME|" packaging/nfpm/localport.yaml >"$work/localport.yaml"

pkg() {
	# pkg <config> <packager> <nfpm arch> <binary> <target>
	NFPM_ARCH="$3" BINARY="$4" nfpm package \
		--config "$1" --packager "$2" --target "$5" >/dev/null
}

rm -rf "$out/deb" "$out/rpm" "$out/apk"
mkdir -p "$out/deb" "$out/rpm"

echo ">>> deb"
for a in amd64:amd64 arm64:arm64 arm6:arm; do
	pkg "$work/localport.yaml" deb "${a%%:*}" "$dist/localport-linux-${a#*:}" "$out/deb/"
done
pkg packaging/nfpm/keyring.yaml deb all "" "$out/deb/"

echo ">>> rpm"
for a in amd64:amd64 arm64:arm64; do
	pkg "$work/localport.yaml" rpm "${a%%:*}" "$dist/localport-linux-${a#*:}" "$out/rpm/"
done
pkg packaging/nfpm/keyring.yaml rpm all "" "$out/rpm/"

# apk fetches <repository>/<arch>/<name>-<version>.apk.
echo ">>> apk"
for a in amd64:amd64:x86_64 arm64:arm64:aarch64 arm6:arm:armhf arm7:arm:armv7; do
	IFS=: read -r nfpm_arch bin apk_arch <<<"$a"
	mkdir -p "$out/apk/$apk_arch"
	pkg "$work/localport.yaml" apk "$nfpm_arch" "$dist/localport-linux-$bin" \
		"$out/apk/$apk_arch/localport-$PKG_VERSION-r1.apk"
done

(cd "$out" && find . -type f | sed 's|^\./|    |' | LC_ALL=C sort)

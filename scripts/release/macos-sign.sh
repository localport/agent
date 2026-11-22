#!/usr/bin/env bash
# Signs the darwin release binaries in <bin-dir> with the hardened runtime
# (macOS only): localport-darwin-<arch> as io.localport.localport, and
# Localport.app around localport-session_darwin_<arch> as io.localport.session.
# Verifies each signature, then packs the app as localport-session-darwin-<arch>.tar.gz.
#
#   scripts/release/macos-sign.sh <bin-dir>
#
# Environment:
#   VERSION              release tag; the app's version is its X.Y.Z, or
#                        0.0.0 for any other value
#   MACOS_SIGN_KEYCHAIN  keychain holding the release signing identity, the
#                        certificate in MACOS_SIGN_CERT. Unset, the binaries
#                        are signed ad-hoc (local and CI builds).
#   MACOS_SIGN_CERT      the identity's certificate, PEM (tests use a throwaway
#                        one); default release/keys/macos-signing.pem
#   SOURCE_DATE_EPOCH    the time every packed file carries; default the
#                        commit time of HEAD.
#
# With a keychain, every signature must name the release certificate as leaf
# and every CLI must embed its fingerprint (a MACOS_RELEASE build); the script
# fails otherwise. The archive is the same for the same input: sorted entries,
# fixed times, no gzip timestamp.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
bin="$(cd "${1:?usage: macos-sign.sh <bin-dir>}" && pwd)"
cert="${MACOS_SIGN_CERT:-$root/release/keys/macos-signing.pem}"
archs="amd64 arm64"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = Darwin ] || die "macos-sign.sh needs macOS"

version=0.0.0
if [[ "${VERSION:-}" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)(-.*)?$ ]]; then
	version="${BASH_REMATCH[1]}"
fi

epoch="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}"
[[ "$epoch" =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH is not a number of seconds: $epoch"
stamp="$(date -u -r "$epoch" +%Y%m%d%H%M.%S)"

identity=-
sha1=""
keychain=()
if [ -n "${MACOS_SIGN_KEYCHAIN:-}" ]; then
	[ -s "$cert" ] || die "$cert is missing; see RELEASING.md, macOS signing identity"
	sha1="$(openssl x509 -in "$cert" -noout -fingerprint -sha1 | sed 's/^.*=//; s/://g' | tr 'A-F' 'a-f')"
	[[ "$sha1" =~ ^[0-9a-f]{40}$ ]] || die "cannot read the SHA-1 fingerprint of $cert"
	identity="$sha1"
	keychain=(--keychain "$MACOS_SIGN_KEYCHAIN")
else
	echo "MACOS_SIGN_KEYCHAIN is unset: signing ad-hoc, not with the release identity"
fi

# sign <identifier> <path>
sign() {
	codesign --force --sign "$identity" ${keychain[@]+"${keychain[@]}"} \
		--options runtime --timestamp=none --identifier "$1" "$2"
}

# check <identifier> <path>: a strict, valid signature with the hardened
# runtime that meets the identifier and, for a release, the certificate.
check() {
	local req="identifier \"$1\""
	[ -z "$sha1" ] || req="$req and certificate leaf = H\"$sha1\""
	codesign --verify --strict "$2" || die "$2: signature does not verify"
	codesign --verify --strict -R="$req" "$2" || die "$2: signature does not meet $req"
	# Captured first: grep -q exits early and pipefail fails on the broken pipe.
	local out
	if [ -n "$sha1" ]; then
		out="$(codesign -d -r- "$2" 2>&1)"
		grep -qF "certificate leaf = H\"$sha1\"" <<<"$out" ||
			die "$2: designated requirement does not name the release certificate"
	fi
	out="$(codesign --display --verbose=1 "$2" 2>&1)"
	grep -Eq '^CodeDirectory .*flags=0x[0-9a-f]+\([^)]*runtime' <<<"$out" ||
		die "$2: no hardened runtime"
	echo "signed $2 as $1${sha1:+ with the release certificate $sha1}"
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

for arch in $archs; do
	cli="$bin/localport-darwin-$arch"
	session="$bin/localport-session_darwin_$arch"
	[ -f "$cli" ] || die "$cli is missing"
	[ -f "$session" ] || die "$session is missing"

	if [ -n "$sha1" ]; then
		grep -aqF "$sha1" "$cli" ||
			die "$cli does not embed the release certificate $sha1: build it with MACOS_RELEASE=1"
	fi
	sign io.localport.localport "$cli"
	check io.localport.localport "$cli"

	rm -rf "${work:?}/$arch"
	app="$work/$arch/Localport.app"
	mkdir -p "$app/Contents/MacOS"
	sed "s/@VERSION@/$version/g" "$root/packaging/macos/Info.plist.in" >"$app/Contents/Info.plist"
	cp "$session" "$app/Contents/MacOS/localport-session"
	chmod 0755 "$app/Contents/MacOS/localport-session"
	sign io.localport.session "$app"
	check io.localport.session "$app"

	find "$app" -exec env TZ=UTC touch -h -t "$stamp" {} +
	(cd "$work/$arch" && find Localport.app | LC_ALL=C sort) |
		tar -C "$work/$arch" --no-mac-metadata --uid 0 --gid 0 --uname root --gname wheel \
			--options gzip:!timestamp -n -T - -czf "$bin/localport-session-darwin-$arch.tar.gz"
done

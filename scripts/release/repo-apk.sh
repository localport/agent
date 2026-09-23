#!/bin/sh
# Adds a release's apk packages to the Alpine repository tree, regenerates each
# architecture's APKINDEX and signs it.
#
#   scripts/release/repo-apk.sh <packages-dir> <repo-dir>
#
# Runs in the Alpine image pinned by the Makefile (`make repo-apk`), which
# provides apk and abuild-sign.
#
# Environment:
#   APK_KEY_FILE   RSA private key (PEM) that signs the indexes
#   KEYS_DIR       public keys, default release/keys; holds <name>.rsa.pub
#   KEEP           versions kept per architecture, default 10
#
# Layout: alpine/stable/<arch>/{APKINDEX.tar.gz,localport-<version>-r<n>.apk}
set -eu

root="$(cd "$(dirname "$0")/../.." && pwd)"
pkgs="$(cd "${1:?usage: repo-apk.sh <packages-dir> <repo-dir>}" && pwd)"
repo="${2:?usage: repo-apk.sh <packages-dir> <repo-dir>}"
mkdir -p "$repo"
repo="$(cd "$repo" && pwd)"
keys="${KEYS_DIR:-$root/release/keys}"
keep="${KEEP:-10}"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ -s "${APK_KEY_FILE:-}" ] || die "APK_KEY_FILE must name the apk signing key"
command -v abuild-sign >/dev/null 2>&1 || die "abuild-sign is required"
set -- "$keys"/*.rsa.pub
[ "$#" -eq 1 ] && [ -s "$1" ] || die "$keys must hold exactly one *.rsa.pub"
pub="$(basename "$1")"

# Lets apk index verify each package signature.
cp "$keys/$pub" "/etc/apk/keys/$pub"

for dir in "$pkgs"/apk/*/; do
	arch="$(basename "$dir")"
	dest="$repo/alpine/stable/$arch"
	echo ">>> $arch"
	mkdir -p "$dest"
	cp "$dir"*.apk "$dest/"

	# Keep the newest $keep versions.
	find "$dest" -maxdepth 1 -type f -name 'localport-*.apk' |
		sed 's|.*/localport-\(.*\)\.apk$|\1|' |
		sort -V |
		head -n "-$keep" |
		while IFS= read -r version; do
			echo "    prune localport-$version.apk"
			rm -f "$dest/localport-$version.apk"
		done

	rm -f "$dest/APKINDEX.tar.gz"
	apk index --quiet --description "Localport" \
		--output "$dest/APKINDEX.tar.gz" "$dest"/*.apk
	abuild-sign -q -k "$APK_KEY_FILE" -p "$pub" "$dest/APKINDEX.tar.gz"
done

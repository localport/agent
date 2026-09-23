#!/usr/bin/env bash
# Moves the package repository tree between a local directory and the R2
# bucket behind pkg.localport.io.
#
#   scripts/release/r2.sh pull <dir>   download the published tree
#   scripts/release/r2.sh push <dir>   publish <dir>
#
# Environment:
#   R2_ACCOUNT_ID, R2_BUCKET                    the bucket
#   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY    an R2 token scoped to it
#
# push uploads packages, then indexes, then the signed entry points (InRelease,
# repomd.xml, APKINDEX.tar.gz), then deletes removed files. Packages are cached
# for a year, indexes are revalidated.
set -euo pipefail

cmd="${1:?usage: r2.sh pull|push <dir>}"
dir="${2:?usage: r2.sh pull|push <dir>}"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

: "${R2_ACCOUNT_ID:?R2_ACCOUNT_ID is required}"
: "${R2_BUCKET:?R2_BUCKET is required}"
: "${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID is required}"
: "${AWS_SECRET_ACCESS_KEY:?AWS_SECRET_ACCESS_KEY is required}"
command -v aws >/dev/null 2>&1 || die "the AWS CLI is required"

export AWS_DEFAULT_REGION=auto
s3=(aws s3 --endpoint-url "https://$R2_ACCOUNT_ID.r2.cloudflarestorage.com" --only-show-errors)
bucket="s3://$R2_BUCKET"

readonly immutable="public, max-age=31536000, immutable"
readonly revalidate="no-cache"

upload() {
	# upload <cache-control> <include patterns...>
	local cache="$1"
	shift
	local filters=(--exclude '*')
	for p in "$@"; do filters+=(--include "$p"); done
	"${s3[@]}" sync "$dir" "$bucket" "${filters[@]}" \
		--cache-control "$cache" --checksum-algorithm CRC32
}

case "$cmd" in
pull)
	mkdir -p "$dir"
	"${s3[@]}" sync "$bucket" "$dir"
	;;
push)
	[ -d "$dir" ] || die "$dir does not exist"
	upload "$immutable" '*.deb' '*.rpm' '*.apk' '*/by-hash/*' '*/repodata/*-*'
	upload "$revalidate" '*/Packages' '*/Packages.gz' \
		'localport-archive-keyring.gpg' '*.rsa.pub' 'RPM-GPG-KEY-localport'
	upload "$revalidate" '*/Release' '*/Release.gpg' '*/InRelease' \
		'*/repomd.xml' '*/repomd.xml.asc' '*/APKINDEX.tar.gz'
	"${s3[@]}" sync "$dir" "$bucket" --delete --exclude '*' \
		--include '*.deb' --include '*.rpm' --include '*.apk' \
		--include '*/by-hash/*' --include '*/repodata/*'
	;;
*)
	die "unknown command $cmd; use pull or push"
	;;
esac

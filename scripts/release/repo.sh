#!/usr/bin/env bash
# Adds a release's deb and rpm packages to the repository tree, regenerates the
# indexes and signs them.
#
#   scripts/release/repo.sh <packages-dir> <repo-dir>
#
# Runs in the Debian image pinned by the Makefile (`make repo`), which provides
# apt-ftparchive, createrepo_c, rpm and gpg.
#
# Environment:
#   REPO_GPG_KEY_FILE    OpenPGP private key that signs the indexes
#   REPO_GPG_PASSPHRASE  its passphrase, when it has one
#   KEEP                 versions kept per package, default 10
#
# New packages are merged into <repo-dir>, older versions beyond KEEP are
# removed, and every index is rebuilt.
#
# Layout:
#   deb/pool/main/l/<package>/*.deb
#   deb/dists/stable/{Release,InRelease,Release.gpg}
#   deb/dists/stable/main/binary-<arch>/{Packages,Packages.gz,by-hash/}
#   rpm/packages/*.rpm   rpm/repodata/{repomd.xml,repomd.xml.asc,...}
set -euo pipefail

pkgs="$(cd "${1:?usage: repo.sh <packages-dir> <repo-dir>}" && pwd)"
repo="${2:?usage: repo.sh <packages-dir> <repo-dir>}"
mkdir -p "$repo"
repo="$(cd "$repo" && pwd)"
keep="${KEEP:-10}"

readonly suite="stable"
readonly component="main"
readonly deb_arches="amd64 arm64 armhf"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ -s "${REPO_GPG_KEY_FILE:-}" ] || die "REPO_GPG_KEY_FILE must name the repository signing key"
for tool in apt-ftparchive createrepo_c dpkg-deb rpm gpg; do
	command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done
[[ "$keep" =~ ^[1-9][0-9]*$ ]] || die "KEEP must be a positive integer"

GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
trap 'gpgconf --kill gpg-agent >/dev/null 2>&1 || true; rm -rf "$GNUPGHOME"' EXIT

gpg_opts=(--batch --yes --pinentry-mode loopback --passphrase-fd 0)
gpg "${gpg_opts[@]}" --quiet --import "$REPO_GPG_KEY_FILE" <<<"${REPO_GPG_PASSPHRASE:-}"
fpr="$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1 == "fpr" { print $10; exit }')"
[ -n "$fpr" ] || die "no secret key found in REPO_GPG_KEY_FILE"

sign() { gpg "${gpg_opts[@]}" --local-user "$fpr" --digest-algo SHA512 "$@" <<<"${REPO_GPG_PASSPHRASE:-}"; }

# prune <dir> <reader>: keeps the newest $keep versions of each package in dir.
# reader prints "<name> <version>" for one package file.
prune() {
	local dir="$1" reader="$2" index f name version
	index="$(mktemp)"
	while IFS= read -r f; do
		read -r name version < <("$reader" "$f")
		printf '%s\t%s\t%s\n' "$name" "$version" "$f"
	done < <(find "$dir" -type f) >"$index"
	cut -f1 "$index" | sort -u | while IFS= read -r name; do
		awk -F'\t' -v n="$name" '$1 == n { print $2 }' "$index" | sort -u -V | head -n -"$keep" |
			while IFS= read -r version; do
				awk -F'\t' -v n="$name" -v v="$version" '$1 == n && $2 == v { print $3 }' "$index" |
					while IFS= read -r f; do
						echo "    prune $(basename "$f")"
						rm -f "$f"
					done
			done
	done
	rm -f "$index"
}
# ${Package} and ${Version} are dpkg-deb fields.
# shellcheck disable=SC2016
deb_meta() { dpkg-deb --showformat='${Package} ${Version}\n' --show "$1"; }
rpm_meta() { rpm -qp --nosignature --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n' "$1" 2>/dev/null; }

echo ">>> apt"
mkdir -p "$repo/deb/pool/$component"
for f in "$pkgs"/deb/*.deb; do
	# shellcheck disable=SC2016
	name="$(dpkg-deb --showformat='${Package}' --show "$f")"
	dest="$repo/deb/pool/$component/${name:0:1}/$name"
	mkdir -p "$dest"
	cp "$f" "$dest/"
done
prune "$repo/deb/pool" deb_meta

# Indexes are also published by hash (Acquire-By-Hash). The previous
# generation is kept for clients that read the old InRelease.
dists="$repo/deb/dists/$suite"
previous="$(mktemp)"
[ -f "$dists/Release" ] && cp "$dists/Release" "$previous"
find "$dists" -maxdepth 1 -type f -delete 2>/dev/null || true
for arch in $deb_arches; do
	dir="$dists/$component/binary-$arch"
	mkdir -p "$dir"
	rm -f "$dir/Packages" "$dir/Packages.gz"
	(cd "$repo/deb" && apt-ftparchive --arch "$arch" packages "pool/$component") >"$dir/Packages"
	gzip -9n --keep "$dir/Packages"
done
apt-ftparchive \
	-o APT::FTPArchive::DoByHash=true \
	-o APT::FTPArchive::Release::Acquire-By-Hash=yes \
	-o APT::FTPArchive::Release::Origin=Localport \
	-o APT::FTPArchive::Release::Label=Localport \
	-o APT::FTPArchive::Release::Suite="$suite" \
	-o APT::FTPArchive::Release::Codename="$suite" \
	-o APT::FTPArchive::Release::Architectures="$deb_arches" \
	-o APT::FTPArchive::Release::Components="$component" \
	-o APT::FTPArchive::Release::Description="Localport agent packages" \
	release "$dists" >"$repo/deb/Release.tmp"
mv "$repo/deb/Release.tmp" "$dists/Release"
live="$(awk '/^ [0-9a-f]+ +[0-9]+ / { print $1 }' "$dists/Release" "$previous" | sort -u)"
find "$dists" -path '*/by-hash/*' -type f | while IFS= read -r f; do
	grep -qxF "$(basename "$f")" <<<"$live" || rm -f "$f"
done
rm -f "$previous"
sign --clearsign --output "$dists/InRelease" "$dists/Release"
sign --detach-sign --output "$dists/Release.gpg" "$dists/Release"

echo ">>> rpm"
mkdir -p "$repo/rpm/packages"
cp "$pkgs"/rpm/*.rpm "$repo/rpm/packages/"
prune "$repo/rpm/packages" rpm_meta
rm -rf "$repo/rpm/repodata"
# gzip is readable by every dnf and yum version.
createrepo_c --quiet --general-compress-type=gz "$repo/rpm"
sign --detach-sign --armor --output "$repo/rpm/repodata/repomd.xml.asc" "$repo/rpm/repodata/repomd.xml"

echo ">>> signed with $fpr"

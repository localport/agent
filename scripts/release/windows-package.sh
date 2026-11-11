#!/usr/bin/env bash
# Builds the Windows release files from the Windows executables in a stage
# directory, in the order the signing flow needs:
#
#   windows-package.sh uninstaller <stage>         writes <stage>/uninstall.exe (Windows only)
#   windows-package.sh installer <stage> <dist>    writes the installer, the zip and the raw exes to <dist>
#   windows-package.sh check <stage> <out>         compiles both installer passes, anywhere (packaging check)
#
# <stage> holds localport.exe and localport-session.exe (signed, in a
# release), LICENSE, NOTICE and THIRD_PARTY_NOTICES; after `uninstaller`
# and its signing, also uninstall.exe.
#
# Environment:
#   VERSION            release tag, vX.Y.Z
#   MAKENSIS           makensis to run (default: makensis on PATH), NSIS 3.13
#   SOURCE_DATE_EPOCH  zip entry time (seconds)
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

step="${1:?usage: windows-package.sh uninstaller|installer|check <stage> [<dist>]}"
stage="$(cd "${2:?stage directory required}" && pwd)"
: "${VERSION:?VERSION is required (vX.Y.Z or vX.Y.Z-PRERELEASE)}"
[[ "$VERSION" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)(-[0-9A-Za-z.]+)?$ ]] || die "VERSION $VERSION is not vX.Y.Z[-PRERELEASE]"
version="${VERSION#v}"
version4="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}.0"
makensis="${MAKENSIS:-makensis}"

# winpath gives makensis and the Windows programs a native path under Git
# Bash; elsewhere paths pass as they are.
winpath() {
	if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

for f in localport.exe localport-session.exe LICENSE NOTICE THIRD_PARTY_NOTICES; do
	[ -f "$stage/$f" ] || die "$stage/$f is missing"
done

nsis() { # nsis <outfile> [extra defines...]
	local out="$1"; shift
	"$makensis" -V2 -WX -NOCD \
		"-DVERSION=$version" "-DVERSION4=$version4" \
		"-DSRCDIR=$(winpath "$stage")" "-DOUTFILE=$(winpath "$out")" \
		"$@" "$(winpath "$root/packaging/windows/localport.nsi")"
}

case "$step" in
uninstaller)
	# The first pass's program writes the uninstaller beside itself and exits.
	nsis "$stage/uninstaller-writer.exe" -DWRITE_UNINSTALLER
	"$stage/uninstaller-writer.exe"
	rm -f "$stage/uninstaller-writer.exe"
	[ -s "$stage/uninstall.exe" ] || die "the first pass wrote no uninstall.exe"
	;;
installer)
	dist="$(mkdir -p "${3:?dist directory required}" && cd "$3" && pwd)"
	[ -f "$stage/uninstall.exe" ] || die "$stage/uninstall.exe is missing; run the uninstaller step (and its signing) first"
	: "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH is required}"
	nsis "$dist/localport-setup-$version-windows-amd64.exe"
	(cd "$root" && go run ./scripts/release/zipdist "$dist/localport-windows-amd64.zip" \
		"$stage/localport.exe" "$stage/localport-session.exe" \
		"$stage/LICENSE" "$stage/NOTICE" "$stage/THIRD_PARTY_NOTICES")
	# The raw assets install.ps1's per-user path downloads, byte for byte the
	# files in the zip.
	cp "$stage/localport.exe" "$dist/localport-windows-amd64.exe"
	cp "$stage/localport-session.exe" "$dist/localport-session-windows-amd64.exe"
	;;
check)
	out="$(mkdir -p "${3:?output directory required}" && cd "$3" && pwd)"
	# Compiles both passes. The writer cannot run off Windows, so the second
	# pass embeds a copy of the writer in place of uninstall.exe: this checks
	# the script compiles, not the uninstaller.
	nsis "$out/uninstaller-writer.exe" -DWRITE_UNINSTALLER
	work="$(mktemp -d)"
	trap 'rm -rf "$work"' EXIT
	cp "$stage"/localport.exe "$stage"/localport-session.exe "$stage"/LICENSE "$stage"/NOTICE "$stage"/THIRD_PARTY_NOTICES "$work/"
	cp "$out/uninstaller-writer.exe" "$work/uninstall.exe"
	stage="$work"
	nsis "$out/localport-setup-$version-windows-amd64.exe"
	;;
*)
	die "unknown step $step"
	;;
esac

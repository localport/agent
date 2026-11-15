#!/usr/bin/env bash
# Generates the VERSIONINFO resources of the Windows executables (ProductName,
# CompanyName, FileDescription, ProductVersion, FileVersion) from
# packaging/windows/winres.json.in into cmd/<name>/rsrc_windows_amd64.syso,
# which only the windows/amd64 build links.
#
#   scripts/release/winres.sh <version>
#
# <version> is the release tag (vX.Y.Z[-PRERELEASE]) or any other build
# version; one without a leading X.Y.Z gets 0.0.0.0 as its numeric version.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
version="${1:?usage: winres.sh <version>}"
version="${version#v}"
version4="$(printf '%s' "$version" | sed -nE 's/^([0-9]+)\.([0-9]+)\.([0-9]+).*/\1.\2.\3.0/p')"
version4="${version4:-0.0.0.0}"

mkdir -p bin
for c in "localport:Localport agent" "localport-session:Localport session launcher"; do
	name="${c%%:*}"
	desc="${c#*:}"
	sed -e "s|@VERSION@|$version|g" -e "s|@VERSION4@|$version4|g" \
		-e "s|@NAME@|$name|g" -e "s|@DESCRIPTION@|$desc|g" \
		packaging/windows/winres.json.in >"bin/winres-$name.json"
	# No --file-version or --product-version: they also overwrite the string
	# ProductVersion in every language, which the template sets to $version.
	go run github.com/tc-hib/go-winres@v0.3.3 make --in "bin/winres-$name.json" --arch amd64 \
		--out "cmd/$name/rsrc"
done

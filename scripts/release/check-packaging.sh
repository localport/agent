#!/usr/bin/env bash
# The Windows packaging check (make check-packaging): cross-builds both
# Windows executables with their VERSIONINFO resources and the release zip on
# this machine, then, in the packaging image (packaging/windows/Dockerfile),
# compiles both NSIS installer passes and validates the rendered Scoop and
# winget manifests against their pinned schemas. Needs Docker; the image is
# built once and cached.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
work="bin/check-packaging"
version=v0.0.0
image=localport-packaging-check

rm -rf "$work"
mkdir -p "$work/stage" "$work/dist" "$work/rendered"

scripts/release/winres.sh "$version"
for cmd in localport localport-session; do
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$version" \
		-o "$work/stage/$cmd.exe" "./cmd/$cmd"
done
cp LICENSE NOTICE THIRD_PARTY_NOTICES "$work/stage/"
SOURCE_DATE_EPOCH=0 go run ./scripts/release/zipdist "$work/dist/localport-windows-amd64.zip" \
	"$work/stage/localport.exe" "$work/stage/localport-session.exe" \
	"$work/stage/LICENSE" "$work/stage/NOTICE" "$work/stage/THIRD_PARTY_NOTICES"
cp "$work/stage/localport.exe" "$work/dist/localport-windows-amd64.exe"

docker build --quiet -t "$image" -f packaging/windows/Dockerfile packaging/windows >/dev/null
docker run --rm --user "$(id -u):$(id -g)" -v "$root:/src" -w /src -e VERSION="$version" "$image" bash -euc '
	scripts/release/windows-package.sh check '"$work"'/stage '"$work"'/dist
	# Manifests render from checksums.txt; the other platforms are not built
	# here, so their names carry the hash of an empty file.
	cd '"$work"'/dist
	empty=$(sha256sum </dev/null | cut -d" " -f1)
	{ sha256sum localport-windows-amd64.exe localport-windows-amd64.zip localport-setup-0.0.0-windows-amd64.exe
	  for n in localport-darwin-arm64 localport-darwin-amd64 localport-linux-arm64 localport-linux-amd64; do echo "$empty  $n"; done
	} >checksums.txt
	cd /src
	scripts/release/manifests.sh render '"$work"'/dist '"$work"'/rendered
	python3 -I packaging/windows/validate_manifests.py '"$work"'/rendered /schemas/winget /schemas/scoop.json
'
echo "check-packaging: installer compiled, manifests valid"

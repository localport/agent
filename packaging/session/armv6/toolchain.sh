#!/usr/bin/env bash
# Builds the ARMv6 hard-float glibc cross toolchain and the libpam sysroot
# for the 32-bit ARM glibc localport-session build (Raspberry Pi OS on
# Pi Zero and Pi 1). Linux hosts only; CI runs it and caches <dir>.
#
#   packaging/session/armv6/toolchain.sh <dir>
#
# Output:
#   <dir>/armv6-rpi-linux-gnueabihf   crosstool-ng toolchain: ARMv6, VFP,
#                                     hard float, glibc 2.36, gcc 12
#   <dir>/pam                         libpam headers and libraries from
#                                     Raspbian bookworm (ARMv6 armhf)
#
# crosstool-ng verifies every source tarball it downloads against the
# digests it ships (CT_VERIFY_DOWNLOAD_DIGEST). libpam comes from Raspbian
# bookworm because its libpam needs glibc 2.34 at most, under the toolchain's
# 2.36, and Raspbian is the ARMv6 armhf build Raspberry Pi OS ships. Each
# .deb is pinned by its SHA-256 from the bookworm Packages index.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
dir="${1:?usage: toolchain.sh <dir>}"
mkdir -p "$dir"
dir="$(cd "$dir" && pwd)"

readonly target=armv6-rpi-linux-gnueabihf
readonly ctng_version=1.29.0
readonly ctng_sha256=1e0c5efcf2af674993b74a1783fe78727c8d34b500ebab07eb1bb0a45c8fcc87
readonly raspbian=https://archive.raspbian.org/raspbian
# <sha256> <pool path>
readonly debs="
faf626003263877261b794f6eebfe906d5cbc486882bcec0fd8574ffd907e318 pool/main/p/pam/libpam0g_1.5.2-6+deb12u2_armhf.deb
acca7de5e2f176c587eaf0223a775cacbc1334cd42ac576890efc584c1a57e94 pool/main/p/pam/libpam0g-dev_1.5.2-6+deb12u2_armhf.deb
869626194e6f224310f62e719a9973550b84d7bf21fcefbed0a95a5abf854f9f pool/main/a/audit/libaudit1_3.0.9-1_armhf.deb
608d82c836b6db0ca6e8ebff920b2c8476bbfeac28b2dde4066ccbf58438fe15 pool/main/libc/libcap-ng/libcap-ng0_0.8.3-1+b1_armhf.deb
"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fetch() {
	# fetch <url> <sha256> <file>
	curl -fsSL --proto '=https' --retry 3 -o "$3" "$1"
	echo "$2  $3" | sha256sum --check --strict --quiet -
}

if [ ! -x "$dir/$target/bin/$target-gcc" ]; then
	echo ">>> crosstool-ng $ctng_version"
	fetch "https://github.com/crosstool-ng/crosstool-ng/releases/download/crosstool-ng-$ctng_version/crosstool-ng-$ctng_version.tar.xz" \
		"$ctng_sha256" "$work/ctng.tar.xz"
	tar -xJf "$work/ctng.tar.xz" -C "$work"
	(cd "$work/crosstool-ng-$ctng_version" &&
		./configure --prefix="$work/ctng" >/dev/null &&
		make -s >/dev/null &&
		make -s install >/dev/null)

	echo ">>> toolchain $target"
	mkdir -p "$work/build"
	(cd "$work/build" &&
		"$work/ctng/bin/ct-ng" defconfig DEFCONFIG="$here/crosstool.defconfig" &&
		CT_PREFIX="$dir" "$work/ctng/bin/ct-ng" build) || {
		tail -n 200 "$work/build/build.log" >&2 || true
		exit 1
	}
fi

echo ">>> libpam sysroot"
rm -rf "$dir/pam"
mkdir -p "$dir/pam"
while read -r sum path; do
	[ -n "$sum" ] || continue
	fetch "$raspbian/$path" "$sum" "$work/pkg.deb"
	dpkg-deb -x "$work/pkg.deb" "$dir/pam"
done <<<"$debs"
# The -dev symlinks are absolute (/lib/...); point them into the sysroot.
for l in "$dir"/pam/usr/lib/arm-linux-gnueabihf/*.so; do
	t="$(readlink "$l")"
	case "$t" in
	/*) ln -sfn "../../..$t" "$l" ;;
	esac
done
[ -e "$dir/pam/usr/lib/arm-linux-gnueabihf/libpam.so" ] || {
	echo "error: libpam.so does not resolve in $dir/pam" >&2
	exit 1
}
echo "toolchain ready in $dir"

#!/usr/bin/env bash
# Builds the OpenWrt package with the OpenWrt SDK and indexes the feed.
# Linux hosts only; the release workflow runs it.
#
#   packaging/openwrt/sdk.sh build <package arch> <version> <out dir>
#       builds packaging/openwrt/localport from the checked-out tree with the
#       SDK of <package arch>; writes <out dir>/localport-openwrt-<arch>.apk
#   packaging/openwrt/sdk.sh index <feed dir> <private key>
#       writes <feed dir>/packages.adb over every .apk in <feed dir>, signed
#       with the ECDSA P-256 key (PEM), using the SDK's apk-tools 3
#   packaging/openwrt/sdk.sh series
#       prints the OpenWrt release series of the pinned SDKs, the feed
#       directory name under openwrt/
#
# <version> is X.Y.Z (the tag without "v"). Each SDK is pinned by the SHA-256
# in the release's sha256sums. SDK_DIR names a directory for downloads and
# unpacked SDKs (default: a temporary directory, removed on exit).
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"

readonly release=25.12.6
readonly base="https://downloads.openwrt.org/releases/$release/targets"
# <package arch> <target/subtarget> <SDK file> <sha256>
readonly sdks="
x86_64 x86/64 openwrt-sdk-25.12.6-x86-64_gcc-14.3.0_musl.Linux-x86_64.tar.zst 1864152619092e781fa36a401960c8e9ae42d6a364c44ee5f0b197ca5f3c0fcc
aarch64_generic armsr/armv8 openwrt-sdk-25.12.6-armsr-armv8_gcc-14.3.0_musl.Linux-x86_64.tar.zst cbf3343bc3d6dc6180fc84077b966c13596a79904adaadbfe68409d563b0b596
aarch64_cortex-a53 mediatek/filogic openwrt-sdk-25.12.6-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64.tar.zst 1c04ac47bdfc361d6aab299eb520d570e368013dedcb8d29cf39dc7168ae642e
arm_cortex-a7_neon-vfpv4 ipq40xx/generic openwrt-sdk-25.12.6-ipq40xx-generic_gcc-14.3.0_musl_eabi.Linux-x86_64.tar.zst 72b2a064190a46b8026e192e29b8ff357dc040850eb3309573124509acbb8a05
arm_arm1176jzf-s_vfp bcm27xx/bcm2708 openwrt-sdk-25.12.6-bcm27xx-bcm2708_gcc-14.3.0_musl_eabi.Linux-x86_64.tar.zst 4f4270db0bb770de03718a1b8944e41c803b8b4f09a83f7285d69337f41df4fc
mipsel_24kc ramips/mt7621 openwrt-sdk-25.12.6-ramips-mt7621_gcc-14.3.0_musl.Linux-x86_64.tar.zst e4e3f25962ddf3ed55207fed456ecd1d6e55f3482c976b3183a640df6ef0adf0
mips_24kc ath79/generic openwrt-sdk-25.12.6-ath79-generic_gcc-14.3.0_musl.Linux-x86_64.tar.zst 941c19d4787944e569bc0ca7fb4b6d0f4387ba24d188900bf0ffb6787fee31c6
riscv64_generic starfive/generic openwrt-sdk-25.12.6-starfive-generic_gcc-14.3.0_musl.Linux-x86_64.tar.zst 4551bd535a7a4cf668a3c323f906a373bfdb44d5f830b9922c64ef53543ba260
"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

if [ -n "${SDK_DIR:-}" ]; then
	mkdir -p "$SDK_DIR"
	work="$(cd "$SDK_DIR" && pwd)"
else
	work="$(mktemp -d)"
	trap 'rm -rf "$work"' EXIT
fi

# sdk <package arch>: downloads and unpacks the SDK, prints its directory.
sdk() {
	local arch="$1" a target file sum
	while read -r a target file sum; do
		[ "$a" = "$arch" ] && break
	done <<<"$sdks"
	[ "$a" = "$arch" ] || die "no OpenWrt $release SDK for package arch $arch"
	local dir="$work/${file%.tar.zst}"
	if [ ! -d "$dir" ]; then
		curl -fsSL --proto '=https' --retry 3 -o "$work/$file" "$base/$target/$file"
		echo "$sum  $work/$file" | sha256sum --check --strict --quiet - || die "$file: checksum mismatch"
		tar --zstd -xf "$work/$file" -C "$work"
		rm -f "$work/$file"
	fi
	[ -d "$dir" ] || die "$file did not unpack to $dir"
	printf '%s' "$dir"
}

build() {
	local arch="${1:?usage: sdk.sh build <package arch> <version> <out dir>}"
	local version="${2:?usage: sdk.sh build <package arch> <version> <out dir>}"
	local out="${3:?usage: sdk.sh build <package arch> <version> <out dir>}"
	[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version $version is not X.Y.Z"
	mkdir -p "$out"
	out="$(cd "$out" && pwd)"

	local dir src hash feed
	dir="$(sdk "$arch")"

	# The source tarball the package Makefile names, made from this tree.
	src="$dir/dl/localport-$version.tar.gz"
	mkdir -p "$dir/dl"
	git -C "$root" archive --format=tar --prefix="agent-$version/" HEAD | gzip -n >"$src"
	hash="$(sha256sum "$src" | cut -d' ' -f1)"

	feed="$work/feed-$arch"
	rm -rf "$feed"
	mkdir -p "$feed/localport"
	sed -e "s|@VERSION@|$version|" -e "s|@HASH@|$hash|" \
		"$root/packaging/openwrt/localport/Makefile" >"$feed/localport/Makefile"

	(
		cd "$dir"
		cp feeds.conf.default feeds.conf
		echo "src-link localport $feed" >>feeds.conf
		./scripts/feeds update packages localport
		./scripts/feeds install -p packages golang1.27
		./scripts/feeds install -p localport localport
		echo "CONFIG_PACKAGE_localport=m" >>.config
		make defconfig >/dev/null
		make package/localport/compile -j"$(nproc)" V=s
	)

	local apk="$dir/bin/packages/$arch/localport/localport-$version-r1.apk"
	[ -f "$apk" ] || die "the SDK built no $apk"
	cp "$apk" "$out/localport-openwrt-$arch.apk"
	echo "built $out/localport-openwrt-$arch.apk"
}

index() {
	local feed="${1:?usage: sdk.sh index <feed dir> <private key>}"
	local key="${2:?usage: sdk.sh index <feed dir> <private key>}"
	[ -s "$key" ] || die "$key is empty"
	feed="$(cd "$feed" && pwd)"
	key="$(cd "$(dirname "$key")" && pwd)/$(basename "$key")"
	compgen -G "$feed/*.apk" >/dev/null || die "no .apk in $feed"

	local dir apk
	dir="$(sdk x86_64)"
	apk="$dir/staging_dir/host/bin/apk"
	[ -x "$apk" ] || die "the SDK has no $apk"

	# As OpenWrt's package/Makefile (merge-index): packages are unsigned, the
	# index carries the signature.
	(cd "$feed" &&
		"$apk" mkndx --root "$dir" --keys-dir "$dir" --allow-untrusted \
			--output packages.adb ./*.apk &&
		"$apk" adbsign --root "$dir" --keys-dir "$dir" --allow-untrusted \
			--sign-key "$key" packages.adb)
	echo "indexed $feed/packages.adb"
}

cmd="${1:-}"
shift || true
case "$cmd" in
build) build "$@" ;;
index) index "$@" ;;
series) printf '%s\n' "${release%.*}" ;;
*) die "usage: sdk.sh build <package arch> <version> <out dir> | index <feed dir> <private key> | series" ;;
esac

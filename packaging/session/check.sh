#!/bin/sh
# Checks one Linux localport-session build.
#
#   packaging/session/check.sh <binary> <tags> [glibc floor] [arm arch]
#
# A build without the pam tag must not link libpam. With a glibc floor
# (for example 2.28), no symbol may need a newer GLIBC_ version. With an
# ARM arch (for example v6), the ELF attribute Tag_CPU_arch must name it.
# READELF and OBJDUMP select cross binutils; the defaults are readelf and
# objdump.
set -eu

bin="${1:?usage: check.sh <binary> <tags> [glibc floor] [arm arch]}"
tags="${2-}"
floor="${3-}"
arch="${4-}"
readelf="${READELF:-readelf}"
objdump="${OBJDUMP:-objdump}"

die() { printf 'error: %s: %s\n' "$bin" "$*" >&2; exit 1; }

[ -f "$bin" ] || die "missing"

case ",$tags," in
*,pam,*) ;;
*) if "$readelf" -d "$bin" | grep -q 'libpam'; then die "built without pam but links libpam"; fi ;;
esac

if [ -n "$floor" ]; then
	max=$("$objdump" -T "$bin" | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' |
		sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1)
	[ -n "$max" ] || die "no GLIBC_ symbol versions; not a glibc build"
	top=$(printf '%s\n%s\n' "$max" "$floor" | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1)
	[ "$top" = "$floor" ] || die "needs GLIBC_$max, floor is $floor"
	echo "$bin: max GLIBC_$max, floor $floor"
fi

if [ -n "$arch" ]; then
	got=$("$readelf" -A "$bin" | sed -n 's/^ *Tag_CPU_arch: *//p')
	[ "$got" = "$arch" ] || die "Tag_CPU_arch is '${got:-none}', want $arch"
	echo "$bin: Tag_CPU_arch $got"
fi

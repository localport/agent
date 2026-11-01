#!/bin/sh
# Creates the system group and user "localport" that the agent runs as.
# Idempotent. Package removal leaves both; `localport service uninstall`
# removes the user.
set -e

name=localport

nologin=/bin/false
for f in /usr/sbin/nologin /sbin/nologin; do
	if [ -x "$f" ]; then
		nologin=$f
		break
	fi
done

if command -v useradd >/dev/null 2>&1; then
	getent group "$name" >/dev/null 2>&1 || groupadd --system "$name"
	getent passwd "$name" >/dev/null 2>&1 ||
		useradd --system --gid "$name" --no-create-home --home-dir /nonexistent \
			--shell "$nologin" --comment "Localport agent" "$name"
elif command -v adduser >/dev/null 2>&1; then
	# BusyBox (Alpine without shadow).
	grep -q "^$name:" /etc/group || addgroup -S "$name"
	id -u "$name" >/dev/null 2>&1 ||
		adduser -S -D -H -h /var/empty -s "$nologin" -G "$name" -g "Localport agent" "$name"
else
	echo "localport: no useradd or adduser; create the system user and group $name" >&2
	exit 1
fi

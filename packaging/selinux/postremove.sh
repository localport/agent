#!/bin/sh
# Removes the localport policy module when the package is erased ($1 = 0);
# an upgrade ($1 = 1) keeps the module the new package installed.
set -e

if [ "$1" -eq 0 ]; then
	semodule -n -s targeted -X 200 -r localport
	if selinuxenabled; then
		load_policy
		restorecon -i -R /usr/bin/localport /usr/bin/localport-session \
			/etc/localport-device /run/localport
	fi
fi

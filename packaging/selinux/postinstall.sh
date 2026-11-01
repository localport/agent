#!/bin/sh
# Installs or upgrades the localport policy module in the targeted store at
# priority 200 (distribution modules use 100), then labels the installed paths.
set -e

semodule -n -s targeted -X 200 -i /usr/share/selinux/packages/targeted/localport.cil
if selinuxenabled; then
	load_policy
	restorecon -i -R /usr/bin/localport /usr/bin/localport-session \
		/etc/localport-device /run/localport
fi

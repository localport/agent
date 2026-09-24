#!/usr/bin/env bash
# Installs and runs the agent from a repository tree on each supported
# distribution, using the documented setup steps.
#
#   scripts/release/repo-test.sh <repo-dir> [<keys-dir>]
#
# Needs Docker. Images run on the host architecture.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
repo="$(cd "${1:?usage: repo-test.sh <repo-dir> [<keys-dir>]}" && pwd)"
keys="$(cd "${2:-$root/release/keys}" && pwd)"

apk_pub="$(cd "$keys" && ls ./*.rsa.pub)"
apk_pub="${apk_pub#./}"

net="localport-repo-test-$$"
server="localport-repo-$$"
cleanup() {
	docker rm -f "$server" >/dev/null 2>&1 || true
	docker network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create "$net" >/dev/null
docker run -d --name "$server" --network "$net" --network-alias pkg \
	-v "$repo:/srv:ro" alpine:3.24 \
	sh -c 'apk add -q --no-cache busybox-extras && exec httpd -f -p 80 -h /srv' >/dev/null
for _ in $(seq 100); do
	docker exec "$server" wget -q -O /dev/null http://127.0.0.1/deb/dists/stable/InRelease 2>/dev/null && break
	sleep 0.2
done

client() {
	# client <image> <script>
	echo ">>> $1"
	docker run --rm --network "$net" -v "$keys:/keys:ro" "$1" sh -euc "$2"
}

apt_setup='
	export DEBIAN_FRONTEND=noninteractive
	install -m 0644 /keys/localport-archive-keyring.gpg /usr/share/keyrings/localport-archive-keyring.gpg
	echo "deb [signed-by=/usr/share/keyrings/localport-archive-keyring.gpg] http://pkg/deb stable main" \
		>/etc/apt/sources.list.d/localport.list
	apt-get update -qq -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/localport.list \
		-o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0
	apt-get install -qq -y --no-install-recommends localport localport-archive-keyring >/dev/null
	localport version
'
dnf_setup='
	install -m 0644 /keys/RPM-GPG-KEY-localport /etc/pki/rpm-gpg/RPM-GPG-KEY-localport
	cat >/etc/yum.repos.d/localport.repo <<EOF
[localport]
name=Localport
baseurl=http://pkg/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-localport
EOF
	dnf -q -y --disablerepo="*" --enablerepo=localport install localport localport-archive-keyring
	localport version
'
apk_setup="
	install -m 0644 /keys/$apk_pub /etc/apk/keys/$apk_pub
	echo http://pkg/alpine/stable >>/etc/apk/repositories
	apk add -q localport
	localport version
"

client debian:12 "$apt_setup"
client debian:13 "$apt_setup"
client ubuntu:20.04 "$apt_setup"
client ubuntu:22.04 "$apt_setup"
client ubuntu:24.04 "$apt_setup"
client ubuntu:26.04 "$apt_setup"
client rockylinux/rockylinux:8 "$dnf_setup"
client rockylinux/rockylinux:9 "$dnf_setup"
client rockylinux/rockylinux:10 "$dnf_setup"
client amazonlinux:2023 "$dnf_setup"
client fedora:44 "$dnf_setup"
client alpine:3.21 "$apk_setup"
client alpine:3.24 "$apk_setup"
echo ">>> every client verified and installed the package"

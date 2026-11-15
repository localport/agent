#!/usr/bin/env bash
# Stages a Docker build context of the module's tracked files, so no
# untracked or ignored file (.env, keys, build output) reaches a builder or
# its cache. <dest>/src holds every file `git ls-files` lists, with its
# working-tree content; a deleted tracked file is skipped. With --git,
# <dest>/git is the .git of a depth-1 clone of HEAD made without templates
# and with its origin remote removed: it stamps the VCS information of a
# build of <dest>/src (a dirty tree reads as modified) and carries no host
# config, remote URL, credential setting or hook.
#
#   scripts/release/tracked-context.sh [--git] <dest>
#
# <dest> is an empty directory the caller owns and removes. Used by
# `make build-session-linux`, check-packaging.sh and check-build-context.sh.
set -euo pipefail

git_context=false
if [ "${1:-}" = --git ]; then
	git_context=true
	shift
fi
[ $# -eq 1 ] || { echo "usage: $0 [--git] <dest>" >&2; exit 64; }
dest=$1
[ -d "$dest" ] && [ -z "$(ls -A "$dest")" ] || { echo "$dest: not an empty directory" >&2; exit 64; }

root="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
cd "$root"

mkdir "$dest/src"
git ls-files -z | while IFS= read -r -d '' f; do
	if [ -e "$f" ] || [ -L "$f" ]; then
		printf '%s\0' "$f"
	fi
done | tar --null --no-recursion -T - -cf - | tar -xf - -C "$dest/src"

if $git_context; then
	# file:// makes the clone a copy over the git protocol, never hardlinks or
	# the host's alternates; an empty template adds no hooks; -o names the
	# remote whatever the host's clone.defaultRemoteName says.
	git clone --quiet --depth 1 --template= -o origin "file://$root" "$dest/clone"
	git -C "$dest/clone" remote remove origin
	mv "$dest/clone/.git" "$dest/git"
	rm -rf "$dest/clone"
fi

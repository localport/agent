#!/usr/bin/env bash
# The build context check (make check-build-context): stages the context
# `make build-session-linux` sends (scripts/release/tracked-context.sh) with an
# untracked and an ignored marker file in the tree, and fails when a marker
# reaches the source context, a tracked file is missing from it, or the git
# context carries a remote, a URL, an include or a hook. Removes the markers
# and the staged context on exit.
set -euo pipefail

root="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
cd "$root"

marker=".check-build-context-$$"
ignored="bin/$marker"
ctx="$(mktemp -d)"
trap 'rm -rf "$ctx" "$root/$marker" "$root/$ignored"' EXIT

git check-ignore -q "$ignored" || { echo "check-build-context: $ignored is not ignored" >&2; exit 1; }
mkdir -p bin
echo secret >"$marker"
echo secret >"$ignored"

scripts/release/tracked-context.sh --git "$ctx"

fail() { echo "check-build-context: $*" >&2; exit 1; }
[ ! -e "$ctx/src/$marker" ] || fail "the untracked $marker reached the source context"
[ ! -e "$ctx/src/$ignored" ] || fail "the ignored $ignored reached the source context"
[ -f "$ctx/src/go.mod" ] || fail "the tracked go.mod is missing from the source context"
[ -f "$ctx/src/packaging/session/Dockerfile" ] || fail "the session Dockerfile is missing from the source context"
[ ! -e "$ctx/src/.git" ] || fail "the source context holds a .git"
if config=$(git config --file "$ctx/git/config" --get-regexp '^(remote|include|includeif|url|credential|core\.hookspath)' 2>/dev/null); then
	fail "the git context config carries host settings: $config"
fi
if [ -d "$ctx/git/hooks" ]; then
	hooks=$(find "$ctx/git/hooks" -type f ! -name '*.sample')
	[ -z "$hooks" ] || fail "the git context carries hooks: $hooks"
fi
[ "$(git --git-dir="$ctx/git" rev-parse HEAD)" = "$(git rev-parse HEAD)" ] || fail "the git context is not at HEAD"
echo "check-build-context: tracked files only, git context without remote or hooks"

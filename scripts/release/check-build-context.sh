#!/usr/bin/env bash
# The build context check (make check-build-context): runs
# `make build-session-linux` with a docker stub first on PATH and an untracked
# and an ignored marker file in the tree. The stub inspects the source context
# and the git build context of every `docker buildx build` call while the
# recipe's staged context still exists, records what it found, and builds
# nothing. The check fails when no call was made, a marker reached a source
# context, a tracked file is missing from it, or a git context carries a
# remote, a URL, an include or a hook or is not at HEAD. Removes the markers
# and the records on exit.
set -euo pipefail

root="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
cd "$root"

marker=".check-build-context-$$"
ignored="bin/$marker"
work="$(mktemp -d)"
trap 'rm -rf "$work" "$root/$marker" "$root/$ignored"' EXIT

git check-ignore -q "$ignored" || { echo "check-build-context: $ignored is not ignored" >&2; exit 1; }
mkdir -p bin "$work/stub" "$work/calls"
echo secret >"$marker"
echo secret >"$ignored"

cat >"$work/stub/docker" <<'STUB'
#!/usr/bin/env bash
# docker stub: records, for one buildx build call, what its source context
# (the last argument) and its --build-context git= directory hold. It copies
# nothing, so a recipe that sends the whole tree cannot fill the disk.
set -euo pipefail
git_ctx=
for a in "$@"; do
	case $a in git=*) git_ctx=${a#git=} ;; esac
done
src=${!#}
[ -n "$git_ctx" ] || { echo "docker stub: no git build context in: $*" >&2; exit 1; }
call="$(mktemp -d "$CHECK_BUILD_CONTEXT_CALLS/call.XXXXXX")"
for f in "$CHECK_BUILD_CONTEXT_MARKER" "$CHECK_BUILD_CONTEXT_IGNORED" go.mod packaging/session/Dockerfile .git; do
	if [ -e "$src/$f" ]; then echo "$f"; fi
done >"$call/src"
git config --file "$git_ctx/config" --get-regexp '^(remote|include|includeif|url|credential|core\.hookspath)' >"$call/gitconfig" 2>/dev/null || true
if [ -d "$git_ctx/hooks" ]; then find "$git_ctx/hooks" -type f ! -name '*.sample'; fi >"$call/hooks"
git --git-dir="$git_ctx" rev-parse HEAD >"$call/head"
STUB
chmod +x "$work/stub/docker"

PATH="$work/stub:$PATH" CHECK_BUILD_CONTEXT_CALLS="$work/calls" \
	CHECK_BUILD_CONTEXT_MARKER="$marker" CHECK_BUILD_CONTEXT_IGNORED="$ignored" \
	make --no-print-directory build-session-linux >/dev/null

fail() { echo "check-build-context: $*" >&2; exit 1; }
head="$(git rev-parse HEAD)"
calls=0
for call in "$work"/calls/call.*; do
	[ -d "$call" ] || continue
	calls=$((calls + 1))
	has() { grep -qxF "$1" "$call/src"; }
	! has "$marker" || fail "the untracked $marker reached the source context"
	! has "$ignored" || fail "the ignored $ignored reached the source context"
	has go.mod || fail "the tracked go.mod is missing from the source context"
	has packaging/session/Dockerfile || fail "the session Dockerfile is missing from the source context"
	! has .git || fail "the source context holds a .git"
	[ ! -s "$call/gitconfig" ] || fail "the git context config carries host settings: $(cat "$call/gitconfig")"
	[ ! -s "$call/hooks" ] || fail "the git context carries hooks: $(cat "$call/hooks")"
	[ "$(cat "$call/head")" = "$head" ] || fail "the git context is not at HEAD"
done
[ "$calls" -gt 0 ] || fail "make build-session-linux made no docker buildx build call"
echo "check-build-context: $calls build calls, tracked files only, git context without remote or hooks"

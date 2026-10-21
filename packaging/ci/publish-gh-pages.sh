#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# Rebuild a site from the current branch tip and push it as one orphan commit, as a
# compare-and-swap: the push only succeeds if the branch still is where the build
# started from (git push --force-with-lease). On a rejection (somebody else pushed
# in between) the whole fetch + build + push is repeated, so a concurrent publish of
# the other channel is carried over instead of overwritten.
#
#   packaging/ci/publish-gh-pages.sh <remote> <branch> <site-dir> <message> <build-cmd> [<arg>...]
#
#   remote     git URL of the repository (may carry a token)
#   branch     branch holding the site (gh-pages)
#   site-dir   output directory (recreated per attempt); after success it holds the
#              tree that was pushed (with its .git)
#   message    commit message
#   build-cmd  run as: <build-cmd> [<arg>...] <old-site> <site-dir>, where old-site is
#              the branch tip (an empty directory if the branch does not exist yet),
#              e.g. packaging/apt/publish.sh stable debs
#
# Environment:
#   PUBLISH_ATTEMPTS     attempts before giving up (default 3)
#   PUBLISH_RETRY_DELAY  seconds before attempt n+1: n * delay (default 10)
#
# The CI job is also serialized by its concurrency group (docs/packaging.md); the
# lease is what makes a lost update impossible even if two publishes do overlap.
set -eu
[ $# -ge 5 ] || {
    echo "usage: $0 <remote> <branch> <site-dir> <message> <build-cmd> [<arg>...]" >&2
    exit 2
}
remote=$1 branch=$2 site=$3 msg=$4
shift 4
attempts=${PUBLISH_ATTEMPTS:-3}
delay=${PUBLISH_RETRY_DELAY:-10}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
ref=refs/heads/$branch

n=1
while :; do
    # Where the branch is now: the expected value of the lease ("" = must not exist).
    rm -rf "$work/old"
    git init -q "$work/old"
    if git -C "$work/old" ls-remote --exit-code "$remote" "$ref" > "$work/head"; then
        git -C "$work/old" fetch -q --depth 1 "$remote" "$ref"
        base=$(git -C "$work/old" rev-parse FETCH_HEAD)
        git -C "$work/old" checkout -q --detach "$base"
    else
        rc=$?
        [ "$rc" = 2 ] || { echo "git ls-remote $branch failed (exit $rc)" >&2; exit 1; }
        base=
    fi
    echo "attempt $n/$attempts: $branch at ${base:-(none)}"

    rm -rf "$site"
    mkdir -p "$site"
    "$@" "$work/old" "$site"

    rm -rf "$site/.git"
    git -C "$site" init -q -b "$branch"
    git -C "$site" add -A
    git -C "$site" -c user.name="github-actions[bot]" \
        -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
        commit -q -m "$msg"
    # One orphan commit: the branch does not grow with every published file.
    if git -C "$site" push -q --force-with-lease="$ref:$base" "$remote" "HEAD:$ref"; then
        echo "pushed $(git -C "$site" rev-parse HEAD) to $branch (was ${base:-(none)})"
        exit 0
    fi
    if [ "$n" -ge "$attempts" ]; then
        echo "push to $branch rejected $n times; giving up" >&2
        exit 1
    fi
    echo "push to $branch rejected ($branch moved since ${base:-(none)}?); rebuilding" >&2
    sleep $((n * delay))
    n=$((n + 1))
done

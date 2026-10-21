#!/bin/bash
# shellcheck disable=SC2016  # bash -c snippets take their values as arguments
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# packaging/ci/publish-gh-pages.sh against a local bare repository, with a fake build
# in place of packaging/apt/publish.sh (no reprepro or gpg needed): first publish to a
# missing branch, a concurrent publish of the other channel during the build (push
# rejected by the lease, rebuilt, both channels kept), a branch that keeps moving
# (bounded retries, the other publish is not overwritten), a failing build (no push).
#
# Needs git. No network, no root.
set -euo pipefail
# shellcheck source=tests/lib.sh
. "$(dirname "$0")/../lib.sh"
need git
PG=$REPO/packaging/ci/publish-gh-pages.sh
export PUBLISH_RETRY_DELAY=0 GIT_CONFIG_NOSYSTEM=1 HOME=$T/home
mkdir -p "$HOME"
git config --global init.defaultBranch main
git config --global protocol.file.allow always

# Fake build, called as publish.sh is: fake-build <channel> <old-site> <new-site>.
# Writes <channel>.txt (one line per build of that channel: "<channel> <count>") and
# carries the other files over from the old site. With $T/race-<channel> present, it
# first runs that file (a concurrent publish that finishes while this build runs).
cat > "$T/fake-build" <<'EOF'
#!/bin/sh
set -eu
ch=$1 old=$2 new=$3
r=$T/race-$ch
if [ -e "$r" ]; then
    mv "$r" "$r.run"
    sh "$r.run"
fi
echo "$ch" >> "$T/builds"
(cd "$old" && find . -path ./.git -prune -o -type f -print) | while read -r f; do
    mkdir -p "$new/$(dirname "$f")"
    cp "$old/$f" "$new/$f"
done
echo "$ch $(grep -cx "$ch" "$T/builds")" > "$new/$ch.txt"
EOF
chmod +x "$T/fake-build"
export T
B=$T/remote.git
git init -q --bare "$B"
pub() {  # pub CHANNEL SITE: publish CHANNEL to $B
    "$PG" "$B" gh-pages "$2" "publish $1" "$T/fake-build" "$1"
}

# 1: branch does not exist yet
expect_exit 0 "first publish creates gh-pages" pub stable "$T/site1"
output_has "first publish: no previous branch" 'gh-pages at \(none\)'
check "first publish: stable.txt on gh-pages" bash -c '[ "$(git --git-dir="$1" show gh-pages:stable.txt)" = "stable 1" ]' _ "$B"
check "site dir holds the pushed tree" bash -c '[ "$(git -C "$1" rev-parse HEAD)" = "$(git --git-dir="$2" rev-parse gh-pages)" ]' _ "$T/site1" "$B"

# 2: a testing publish lands while the stable build runs -> lease rejects, rebuild
cat > "$T/race-stable" <<EOF
"$PG" "$B" gh-pages "$T/site-race" "publish testing (concurrent)" "$T/fake-build" testing
EOF
before=$(git --git-dir="$B" rev-parse gh-pages)
expect_exit 0 "stable publish with a concurrent testing publish" pub stable "$T/site2"
output_has "push was rejected once" 'rejected .*rebuilding'
output_has "second attempt" 'attempt 2/3'
check "concurrent publish happened" test -e "$T/race-stable.run"
check "testing kept (carried over from the concurrent push)" bash -c '[ "$(git --git-dir="$1" show gh-pages:testing.txt)" = "testing 1" ]' _ "$B"
check "stable updated (rebuilt on top)" bash -c '[ "$(git --git-dir="$1" show gh-pages:stable.txt)" = "stable 3" ]' _ "$B"
check "gh-pages is one orphan commit" bash -c '[ "$(git --git-dir="$1" rev-list --count gh-pages)" = 1 ]' _ "$B"
check "gh-pages moved" bash -c '[ "$(git --git-dir="$1" rev-parse gh-pages)" != "$2" ]' _ "$B" "$before"
rm -f "$T"/race-*.run

# 3: the branch moves during every build -> give up after PUBLISH_ATTEMPTS, never overwrite
cat > "$T/race-tmpl" <<EOF
cp "$T/race-tmpl" "$T/race-stable"
"$PG" "$B" gh-pages "$T/site-race" "publish testing (concurrent)" "$T/fake-build" testing
EOF
cp "$T/race-tmpl" "$T/race-stable"
expect_exit 1 "branch that keeps moving: gives up" env PUBLISH_ATTEMPTS=2 "$PG" "$B" gh-pages "$T/site3" "publish stable" "$T/fake-build" stable
output_has "says why" 'rejected 2 times; giving up'
check "last concurrent testing publish is on gh-pages" bash -c '[ "$(git --git-dir="$1" show gh-pages:testing.txt)" = "testing 3" ]' _ "$B"
check "stable not overwritten by the failed publish" bash -c '[ "$(git --git-dir="$1" show gh-pages:stable.txt)" = "stable 3" ]' _ "$B"
rm -f "$T"/race-stable "$T"/race-*.run

# 4: a failing build pushes nothing
before=$(git --git-dir="$B" rev-parse gh-pages)
expect_exit nonzero "failing build fails the publish" "$PG" "$B" gh-pages "$T/site4" "publish stable" false
check "failing build: gh-pages unchanged" bash -c '[ "$(git --git-dir="$1" rev-parse gh-pages)" = "$2" ]' _ "$B" "$before"

# 5: unreachable remote fails (not mistaken for a missing branch)
expect_exit 1 "unreachable remote fails" "$PG" "$T/nonexistent.git" gh-pages "$T/site5" "publish stable" "$T/fake-build" stable
output_has "unreachable remote: says ls-remote failed" 'ls-remote gh-pages failed'
expect_exit 2 "usage" "$PG" "$B" gh-pages "$T/site6" "msg"
finish

# shellcheck shell=bash disable=SC2034  # REPO, T_OUT: used by the sourcing tests
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# Helpers for the shell regression tests (sourced). Output follows the e2e suites:
# one "ok   ..." / "FAIL ..." line per check, then a summary; `finish` sets the exit code.
#
# FASTRDP_TESTS_STRICT=1 (CI) turns a missing tool into a failure instead of a skip.
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
T_PASS=0
T_FAIL=0
T=$(mktemp -d /tmp/fastrdp-test.XXXXXX)
T_OUT=$T/.out
trap 'rm -rf "$T"' EXIT

ok() { echo "ok   $1"; T_PASS=$((T_PASS + 1)); }
fail() {
    echo "FAIL $1"
    T_FAIL=$((T_FAIL + 1))
    [ -s "$T_OUT" ] && sed 's/^/     | /' "$T_OUT" | tail -8
    return 0
}

# check DESC CMD...: CMD must succeed (its output goes to $T_OUT)
check() {
    local d=$1
    shift
    if "$@" >"$T_OUT" 2>&1; then ok "$d"; else fail "$d"; fi
}

# expect_exit CODE DESC CMD...: CMD must exit with CODE ("nonzero" = anything but 0)
expect_exit() {
    local want=$1 d=$2 rc=0
    shift 2
    "$@" >"$T_OUT" 2>&1 || rc=$?
    if [ "$rc" = "$want" ] || { [ "$want" = nonzero ] && [ "$rc" != 0 ]; }; then
        ok "$d"
    else
        fail "$d (exit $rc, expected $want)"
    fi
}

# in_dir DIR CMD...: run CMD in DIR (for check/expect_exit)
in_dir() {
    local d=$1
    shift
    (cd "$d" && "$@")
}

# output_has DESC REGEX: the output of the last check/expect_exit matches REGEX
output_has() {
    if grep -Eq -- "$2" "$T_OUT"; then ok "$1"; else fail "$1 (no /$2/ in output)"; fi
}

output_lacks() {
    if grep -Eq -- "$2" "$T_OUT"; then fail "$1 (/$2/ in output)"; else ok "$1"; fi
}

# need TOOL...: skip the whole file (or fail, if FASTRDP_TESTS_STRICT=1) without them
need() {
    local t missing=()
    for t; do command -v "$t" >/dev/null || missing+=("$t"); done
    [ ${#missing[@]} -eq 0 ] && return 0
    if [ "${FASTRDP_TESTS_STRICT:-0}" = 1 ]; then
        echo "FAIL $(basename "$0"): missing ${missing[*]}"
        exit 1
    fi
    echo "SKIP $(basename "$0"): missing ${missing[*]}"
    exit 0
}

finish() {
    echo "$(basename "$0"): $T_PASS passed, $T_FAIL failed"
    [ "$T_FAIL" -eq 0 ]
}

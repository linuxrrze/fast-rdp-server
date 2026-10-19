#!/bin/bash
# Every build dependency a third_party build script needs (--deps) must be in the
# Build-Depends of its package; otherwise clean package builds break late.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fail=0
check() {  # check SCRIPT CONTROL
    local bd
    bd=$(awk '/^Build-Depends:/{f=1; next} f && /^ /{print; next} f{exit}' "$root/$2" |
         tr -d ' ,' | sed 's/([^)]*)//; s/|.*//')
    for dep in $("$root/$1" --deps); do
        case $dep in build-essential|pkg-config) continue ;; esac
        grep -qx "$dep" <<<"$bd" || { echo "$2: Build-Depends lacks $dep (needed by $1)"; fail=1; }
    done
}
check third_party/build-freerdp.sh packaging/freerdp/debian/control
check third_party/build-xrdp.sh packaging/xrdp/debian/control
[ $fail -eq 0 ] && echo "ok   vendored Build-Depends match the build scripts"
exit $fail

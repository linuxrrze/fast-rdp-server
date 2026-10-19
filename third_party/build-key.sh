#!/bin/bash
# build-key.sh freerdp|xrdp
#   Short hash over everything that determines a vendored build: sources.yml, fetch.sh,
#   the build script and the patch series it applies. Same key = same build inputs.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
case ${1:?usage: build-key.sh freerdp|xrdp} in
    freerdp) series=(freerdp) ;;
    xrdp) series=(xrdp xorgxrdp) ;;
    *) echo "build-key.sh: unknown build '$1'" >&2; exit 2 ;;
esac
cd "$root"
files=(third_party/sources.yml third_party/fetch.sh "third_party/build-$1.sh")
for n in "${series[@]}"; do
    [ -f "patches/$n/series" ] || continue
    files+=("patches/$n/series")
    while read -r p; do
        case $p in ''|'#'*) continue ;; esac
        files+=("patches/$n/$p")
    done < "patches/$n/series"
done
cat "${files[@]}" | sha256sum | cut -c1-16

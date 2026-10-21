#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# ansible/roles/base/files/fastrdp-outdated-packages.sh (role base, apt_repo.yml) with a
# fake dpkg-query (installed packages from $T/installed) and the real dpkg for the
# comparisons: own packages by release number (distro and +git suffixes ignored), vendored
# packages by Debian revision without the ~<distro> suffix, only installed (ii) packages,
# bad arguments and a failing dpkg-query refused (exit 2).
#
# Needs dpkg. No root.
set -euo pipefail
# shellcheck source=tests/lib.sh
. "$(dirname "$0")/../lib.sh"
need dpkg
S=$REPO/ansible/roles/base/files/fastrdp-outdated-packages.sh

mkdir -p "$T/bin"
cat > "$T/bin/dpkg-query" <<'EOF'
#!/bin/sh
# the fields the script asks for, for the named packages that are in $T/installed;
# exit 1 if one is unknown (as dpkg-query -W does)
[ -n "${FAKE_DPKG_QUERY_RC:-}" ] && exit "$FAKE_DPKG_QUERY_RC"
shift 2
rc=0
for p; do
    grep "^$p " "$T/installed" || { echo "dpkg-query: no packages found matching $p" >&2; rc=1; }
done
exit $rc
EOF
chmod +x "$T/bin/dpkg-query"
export PATH=$T/bin:$PATH T

run() { "$S" 0.5.0 fastrdp-broker fastrdp-session fastrdp-webgate \
    fastrdp-freerdp3=3.32.2-3 fastrdp-xrdp=0.10.6.1+xorgxrdp0.10.5-2; }

# the case from the field: everything one release behind, webgate not installed
cat > "$T/installed" <<'EOF'
fastrdp-broker 0.4.4~ubuntu26.04 ii
fastrdp-session 0.4.4~ubuntu26.04 ii
fastrdp-freerdp3 3.32.2-2~ubuntu26.04 ii
fastrdp-xrdp 0.10.6.1+xorgxrdp0.10.5-2~ubuntu26.04 ii
EOF
check "older packages listed" run
output_has "own package, installed and required version" '^own fastrdp-broker 0\.4\.4~ubuntu26\.04 0\.5\.0$'
output_has "second own package" '^own fastrdp-session 0\.4\.4~ubuntu26\.04 0\.5\.0$'
output_has "vendored revision bump" '^vendored fastrdp-freerdp3 3\.32\.2-2~ubuntu26\.04 3\.32\.2-3$'
output_lacks "vendored package at the required version" 'fastrdp-xrdp'
output_lacks "not installed: not listed" 'webgate'

# up to date: release builds, main builds (+git) and newer versions print nothing
cat > "$T/installed" <<'EOF'
fastrdp-broker 0.5.0~deb13 ii
fastrdp-session 0.5.0+git20261021210119.27bea23~ubuntu26.04 ii
fastrdp-webgate 0.6.0~deb13 ii
fastrdp-freerdp3 3.32.2-3~deb13 ii
fastrdp-xrdp 0.10.6.1+xorgxrdp0.10.5-3~ubuntu26.04 ii
EOF
check "nothing older" run
if [ -s "$T_OUT" ]; then fail "no output when nothing is older"; else ok "no output when nothing is older"; fi

# a +git build of the previous release is older; removed (rc) and half-installed packages are ignored
cat > "$T/installed" <<'EOF'
fastrdp-broker 0.4.4+git20261020.abcdef0~deb13 ii
fastrdp-session 0.4.4~deb13 rc
fastrdp-webgate 0.4.4~deb13 iU
fastrdp-freerdp3 3.32.1-9~deb13 ii
EOF
check "main build of the previous release" run
output_has "+git build compared by release number" '^own fastrdp-broker 0\.4\.4\+git20261020\.abcdef0~deb13 0\.5\.0$'
output_lacks "removed package (rc) ignored" 'fastrdp-session'
output_lacks "not fully installed (iU) ignored" 'fastrdp-webgate'
output_has "older upstream version of a vendored package" '^vendored fastrdp-freerdp3 3\.32\.1-9~deb13 3\.32\.2-3$'

# numeric comparison, not text: 0.10.0 is newer than 0.9.9
printf 'fastrdp-broker 0.9.9~deb13 ii \n' > "$T/installed"
check "numeric version order" "$S" 0.10.0 fastrdp-broker
output_has "0.9.9 older than 0.10.0" '^own fastrdp-broker 0\.9\.9~deb13 0\.10\.0$'
printf 'fastrdp-broker 0.10.0~deb13 ii \n' > "$T/installed"
check "0.10.0 not older than 0.9.9" "$S" 0.9.9 fastrdp-broker
if [ -s "$T_OUT" ]; then fail "0.10.0 not listed against 0.9.9"; else ok "0.10.0 not listed against 0.9.9"; fi

check "no packages: nothing to do" "$S" 0.5.0

# refused: exit 2 with a message, never an empty (= "nothing older") result
expect_exit 2 "no arguments" "$S"
expect_exit 2 "roles version with a suffix" "$S" 0.5.0~rc1 fastrdp-broker
output_has "names the roles version" "roles version '0\.5\.0~rc1'"
expect_exit 2 "empty roles version" "$S" "" fastrdp-broker
expect_exit 2 "empty vendored version" "$S" 0.5.0 fastrdp-freerdp3=
output_has "names the package" 'fastrdp-freerdp3: required version'
expect_exit 2 "malformed vendored version" "$S" 0.5.0 "fastrdp-freerdp3=3.32 2"
FAKE_DPKG_QUERY_RC=2 expect_exit 2 "dpkg-query failure" "$S" 0.5.0 fastrdp-broker
output_has "names dpkg-query" 'dpkg-query failed \(exit 2\)'
printf 'fastrdp-broker x:y ii \n' > "$T/installed"
expect_exit 2 "installed version dpkg cannot compare" "$S" 0.5.0 fastrdp-broker
output_has "names the package and version" "fastrdp-broker: cannot compare installed version 'x:y'"

finish

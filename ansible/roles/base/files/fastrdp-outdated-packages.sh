#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# Installed fastrdp packages older than the roles (role base, apt_repo.yml; runs on the host).
#
#   fastrdp-outdated-packages.sh ROLES_VERSION [OWN_PACKAGE | VENDORED_PACKAGE=VERSION]...
#
# Prints "own|vendored PACKAGE INSTALLED REQUIRED" for each installed (ii) package that is
# older; nothing if none is. Own packages: release number only (0.5.0~ubuntu26.04 and
# 0.5.0+git... are 0.5.0) against ROLES_VERSION. Vendored packages: full Debian version
# without the ~deb13 / ~ubuntu26.04 distro suffix, compared by dpkg. Exit 2: bad arguments.
set -euo pipefail

die() { echo "fastrdp-outdated-packages.sh: $*" >&2; exit 2; }

[ $# -ge 1 ] || die "usage: ROLES_VERSION [PACKAGE | PACKAGE=VERSION]..."
roles=$1
shift
[[ $roles =~ ^[0-9]+(\.[0-9]+)+$ ]] || die "roles version '$roles' is not a release number"
declare -A want=()      # package -> required version ("" = own package, ROLES_VERSION)
for a; do
    case $a in
        *=*)
            if [ -z "${a#*=}" ] || ! dpkg --validate-version -- "${a#*=}" 2>/dev/null; then
                die "${a%%=*}: required version '${a#*=}' is not a Debian version"
            fi
            want[${a%%=*}]=${a#*=} ;;
        *) want[$a]= ;;
    esac
done
[ ${#want[@]} -gt 0 ] || exit 0

rc=0
out=$(dpkg-query -W -f='${Package} ${Version} ${db:Status-Abbrev}\n' "${!want[@]}" 2>/dev/null) || rc=$?
[ "$rc" -le 1 ] || die "dpkg-query failed (exit $rc)"      # 1: some are not installed

while read -r pkg ver status; do
    [[ ${status:-} == ii* && -n ${want[$pkg]+set} ]] || continue
    if [ -z "${want[$pkg]}" ]; then
        kind=own cur=${ver%%[~+]*} req=$roles
    else
        kind=vendored cur=$(sed -E 's/~(deb|ubuntu)[0-9.]+$//' <<<"$ver") req=${want[$pkg]}
    fi
    lt=0
    dpkg --compare-versions "$cur" lt "$req" || lt=$?
    case $lt in
        0) echo "$kind $pkg $ver $req" ;;
        1) ;;
        *) die "$pkg: cannot compare installed version '$ver' with $req" ;;
    esac
done <<<"$out"

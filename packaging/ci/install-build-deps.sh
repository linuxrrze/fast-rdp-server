#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# Install the tools to build and check packages, then the build dependencies of a
# source tree. Run as root in a ubuntu:26.04 or debian:trixie container.
#
#   packaging/ci/install-build-deps.sh <source-dir|-> [extra packages or ./local.deb ...]
#
# "-" installs only the tools (and the extra packages).
set -eu
[ $# -ge 1 ] || { echo "usage: $0 <source-dir|-> [packages...]" >&2; exit 2; }
dir=$1
shift
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl dpkg-dev git lintian patch "$@"
if [ "$dir" != - ]; then
    apt-get build-dep -y "$dir"
fi

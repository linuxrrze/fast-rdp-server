#!/bin/bash
# shellcheck disable=SC2016  # bash -c snippets take their values as arguments
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# After installing all fastrdp packages (CI "build" job, or a host installed from the
# APT repository): users, paths, library resolution, RPATH/RUNPATH, Python imports,
# the xrdp FFmpeg build. Read-only; run as any user.
set -euo pipefail
# shellcheck source=tests/lib.sh
. "$(dirname "$0")/../lib.sh"
need ldd readelf getent python3

P=/opt/fastrdp
PLUGIN=$P/lib/freerdp3/proxy/libproxy-fastrdp-plugin.so
check "group _fastrdp-broker" getent group _fastrdp-broker
for u in _fastrdp-proxy _fastrdp-web xrdp; do check "user $u" getent passwd "$u"; done
check "proxy module in fastrdp-freerdp3's plugin directory" test -f "$PLUGIN"
for f in "$P/bin/freerdp-proxy" "$P/bin/xfreerdp" "$PLUGIN"; do
    check "$f: all libraries resolve" bash -c '! env -u LD_LIBRARY_PATH ldd "$1" | grep "not found"' _ "$f"
    # ldd prints $ORIGIN paths unnormalized (/opt/fastrdp/bin/../lib/libfreerdp3.so.3)
    check "$f: FreeRDP from $P/lib" \
        bash -c 'l=$(env -u LD_LIBRARY_PATH ldd "$1" | awk "/^[[:space:]]*libfreerdp3\\.so/ {print \$3}")
                 [ -n "$l" ] && [ "$(dirname "$(readlink -f "$l")")" = "$2/lib" ]' _ "$f" "$P"
done
# DT_RPATH (not RUNPATH) on fastrdp-freerdp3's own binaries: wins over LD_LIBRARY_PATH
for f in "$P/bin/freerdp-proxy" "$P/bin/xfreerdp" "$P/lib/libfreerdp-server-proxy3.so.3"; do
    check "$f: DT_RPATH \$ORIGIN/../lib" bash -c 'readelf -d "$1" | grep -F "(RPATH)" | grep -qF "[\$ORIGIN/../lib]"' _ "$f"
done
# the module finds /opt/fastrdp/lib relative to the plugin directory (CMakeLists.txt)
check "proxy module: RUNPATH \$ORIGIN/../.." bash -c 'readelf -d "$1" | grep -E "\((RUNPATH|RPATH)\)" | grep -qF "[\$ORIGIN/../..]"' _ "$PLUGIN"
check "proxy module exports the entry point" bash -c 'readelf --dyn-syms -W "$1" | grep -q " proxy_module_entry_point$"' _ "$PLUGIN"
check "PAM module installed" bash -c 'ls /usr/lib/*/security/pam_fastrdp_token.so'
for s in fastrdp fastrdp-tgt fastrdp-session; do
    check "PAM service /etc/pam.d/$s installed" test -f "/etc/pam.d/$s"
done
check "broker and webgate import" env PYTHONPATH=/usr/lib/fastrdp/python python3 -c 'import fastrdp_broker.server, fastrdp_webgate.app'
ex=$(find /usr/share/doc/fastrdp-broker/examples -name 'broker.toml.example*' 2>/dev/null | head -1) || true
# missing in containers whose dpkg excludes /usr/share/doc (ubuntu image: dpkg.cfg.d/excludes)
check "broker.toml example shipped in /usr/share/doc/fastrdp-broker/examples" test -n "$ex"
case $ex in *.gz) zcat "$ex" > "$T/broker.toml" ;; ?*) cp "$ex" "$T/broker.toml" ;; esac
check "fastrdp-brokerd --check accepts the example config" /usr/sbin/fastrdp-brokerd --check --config "$T/broker.toml"
check "fastrdpctl --help" /usr/sbin/fastrdpctl --help
check "xrdp built with --enable-ffmpeg" bash -c '/usr/sbin/xrdp -v | grep -q -- --enable-ffmpeg'
check "session launcher installed" test -x /usr/libexec/fastrdp/startwm.sh
for u in fastrdp-brokerd fastrdp-proxy fastrdp-webgate xrdp xrdp-sesman; do
    check "$u.service shipped" test -f "/usr/lib/systemd/system/$u.service"
done
finish

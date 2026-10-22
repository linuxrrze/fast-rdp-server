#!/bin/bash
# shellcheck disable=SC2016  # bash -c snippets take their values as arguments
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# After installing all fastrdp packages (CI "build" job, or a host installed from the
# APT repository): users, paths, library resolution, RPATH/RUNPATH, Python imports,
# the xrdp FFmpeg build, the TERMSRV helpers, xrdp site configuration that is no conffile.
# Read-only; run as any user.
set -euo pipefail
# shellcheck source=tests/lib.sh
. "$(dirname "$0")/../lib.sh"
need ldd readelf getent python3 dpkg-query cmp

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
# Kerberos login reminder (backlog K4): autostarted in every desktop session
check "tgt-notify installed" test -x /usr/libexec/fastrdp/tgt-notify
check "tgt-notify autostart entry is a conffile of fastrdp-session" \
    bash -c 'dpkg-query -W -f="\${Conffiles}\n" fastrdp-session | grep -q " /etc/xdg/autostart/fastrdp-tgt-notify.desktop "'
check "tgt-notify --status" /usr/libexec/fastrdp/tgt-notify --config /nonexistent --status
output_has "tgt-notify imports the broker module (defaults without a config file)" '"enabled": true'
check "xrdp-audio installed" test -x /usr/libexec/fastrdp/xrdp-audio
check "xrdp-audio autostart entry is a conffile of fastrdp-session" \
    bash -c 'dpkg-query -W -f="\${Conffiles}\n" fastrdp-session | grep -q " /etc/xdg/autostart/fastrdp-xrdp-audio.desktop "'
check "xrdp-audio does nothing outside xrdp sessions" env -u XRDP_SESSION /usr/libexec/fastrdp/xrdp-audio --autostart
for u in fastrdp-brokerd fastrdp-proxy fastrdp-webgate xrdp xrdp-sesman fastrdp-termsrv-keytab; do
    check "$u.service shipped" test -f "/usr/lib/systemd/system/$u.service"
done
check "fastrdp-termsrv-keytab.path shipped" test -f /usr/lib/systemd/system/fastrdp-termsrv-keytab.path
check "units installed disabled (no enablement links)" \
    bash -c '! ls /etc/systemd/system/*.wants/ 2>/dev/null | grep -E "^(fastrdp-|xrdp)"'

# TERMSRV keytab helpers (fastrdp-broker): packaged in /usr/sbin, settings in /etc/fastrdp
for s in fastrdp-termsrv-check fastrdp-termsrv-keytab; do
    check "$s in /usr/sbin" test -x "/usr/sbin/$s"
done
expect_exit 2 "fastrdp-termsrv-check: no principal exits 2" /usr/sbin/fastrdp-termsrv-check
expect_exit 2 "fastrdp-termsrv-keytab: unknown option exits 2" /usr/sbin/fastrdp-termsrv-keytab -x
check "termsrv.conf is a conffile of fastrdp-broker" \
    bash -c 'dpkg-query -W -f="\${Conffiles}\n" fastrdp-broker | grep -q " /etc/fastrdp/termsrv.conf "'
check "termsrv.conf sets nothing by default" bash -c '! grep -Ev "^[[:space:]]*(#|$)" /etc/fastrdp/termsrv.conf'
check "units run the packaged helper" grep -qx 'ExecStart=/usr/sbin/fastrdp-termsrv-keytab' \
    /usr/lib/systemd/system/fastrdp-termsrv-keytab.service
expect_exit 1 "fastrdp-termsrv-keytab: missing host keytab fails" \
    env FASTRDP_TERMSRV_CONF=/nonexistent /usr/sbin/fastrdp-termsrv-keytab -s /nonexistent
output_has "fastrdp-termsrv-keytab: names the missing keytab" "cannot read /nonexistent"

# xrdp site configuration (fastrdp-xrdp): not conffiles (no dpkg prompts on upgrades),
# created from upstream's defaults by postinst
XRDP_SITE="/etc/xrdp/xrdp.ini /etc/xrdp/sesman.ini /etc/xrdp/gfx.toml /etc/xrdp/startwm.sh
/etc/X11/xrdp/xorg.conf /etc/pam.d/xrdp-sesman"
conffiles=$(dpkg-query -W -f='${Conffiles}\n' fastrdp-xrdp)
for f in $XRDP_SITE; do
    check "$f: not a conffile of fastrdp-xrdp" bash -c '! grep -q " $1 " <<<"$2"' _ "$f" "$conffiles"
    check "$f: default in /usr/share/fastrdp-xrdp/default-config" test -f "/usr/share/fastrdp-xrdp/default-config$f"
    check "$f: created by postinst" cmp "$f" "/usr/share/fastrdp-xrdp/default-config$f"
done
check "startwm.sh executable" test -x /etc/xrdp/startwm.sh
check "other xrdp files stay conffiles (km-*.ini)" bash -c 'grep -q " /etc/xrdp/km-00000407.ini " <<<"$1"' _ "$conffiles"
finish

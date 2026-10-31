#!/bin/bash
# shellcheck disable=SC2016  # bash -c snippets take their values as arguments
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# fastrdp-defaults (broker/sbin) and the maintainer scripts that call it, against a
# DPKG_ROOT laid out as the packages install it: defaults installed where missing,
# upstream's xrdp files replaced in either package order, unchanged files updated and
# changed ones kept on upgrades, purge, the fastrdp-server and keyring scripts.
set -euo pipefail
# shellcheck source=tests/lib.sh
. "$(dirname "$0")/../lib.sh"
need sha256sum cmp diff

DEB=$REPO/debian
UP=/usr/share/fastrdp-xrdp/default-config
XRDP_SITE="/etc/xrdp/xrdp.ini /etc/xrdp/sesman.ini /etc/xrdp/gfx.toml /etc/xrdp/startwm.sh
/etc/X11/xrdp/xorg.conf /etc/pam.d/xrdp-sesman"

# payload ROOT: the files of the fastrdp packages that fastrdp-defaults reads
payload() {
    local r=$1 p
    install -D -m 0755 "$REPO/broker/sbin/fastrdp-defaults" "$r/usr/sbin/fastrdp-defaults"
    # the target's accounts (as root, fastrdp-defaults chowns by them; CI runs as root)
    mkdir -p "$r/etc"
    printf 'root:x:0:0:root:/root:/bin/sh\n_fastrdp-proxy:x:990:990::/nonexistent:/usr/sbin/nologin\n' > "$r/etc/passwd"
    printf 'root:x:0:\n_fastrdp-proxy:x:990:\n' > "$r/etc/group"
    for p in fastrdp-broker fastrdp-proxy-module fastrdp-session fastrdp-server; do
        install -D -m 0644 "$REPO/packaging/defaults/$p.list" "$r/usr/share/$p/defaults.list"
        mkdir -p "$r/usr/share/$p/defaults"
        cp -a "$REPO/packaging/defaults/$p/etc" "$r/usr/share/$p/defaults/"
    done
    install -D -m 0755 "$REPO/broker/session/libexec/startwm.sh" "$r/usr/libexec/fastrdp/startwm.sh"
    install -D -m 0644 "$REPO/broker/session/pam/xrdp-sesman" "$r/usr/share/fastrdp-session/pam.d/xrdp-sesman"
}
# fastrdp-xrdp: upstream's defaults, and its postinst's copy where missing
xrdp_payload() {
    local f
    for f in $XRDP_SITE; do
        mkdir -p "$1$UP$(dirname "$f")"
        echo "upstream $f" > "$1$UP$f"
    done
}
xrdp_postinst() {
    local f
    for f in $XRDP_SITE; do
        [ -e "$1$f" ] || { mkdir -p "$1$(dirname "$f")"; cp -p "$1$UP$f" "$1$f"; }
    done
}
run() { local r=$1 s=$2; shift 2; env DPKG_ROOT="$r" sh "$DEB/$s" "$@"; }
mode() { stat -c %a "$1"; }

# dh_installdeb replaces every #DEBHELPER# token, also one in a comment (0.7.11 CI:
# "postinst: 36: ,: not found"): exactly one per script, on a line of its own
for f in "$DEB"/*.postinst "$DEB"/*.postrm "$DEB"/*.preinst "$DEB"/*.prerm; do
    [ -e "$f" ] || continue
    check "$(basename "$f"): one #DEBHELPER# line" \
        test "$(grep -c DEBHELPER "$f"):$(grep -cx '#DEBHELPER#' "$f")" = 1:1
done

# --- fresh install, fastrdp-xrdp configured first (its postinst copies upstream's files)
R=$T/a
payload "$R"
check "broker postinst" run "$R" fastrdp-broker.postinst configure
output_has "broker.toml installed" "installed /etc/fastrdp/broker.toml"
check "broker.toml = packaged default" cmp "$R/etc/fastrdp/broker.toml" "$REPO/packaging/defaults/fastrdp-broker/etc/fastrdp/broker.toml"
check "broker.toml mode 0600" test "$(mode "$R/etc/fastrdp/broker.toml")" = 600
check "proxy-module postinst" run "$R" fastrdp-proxy-module.postinst configure
check "proxy.ini mode 0640" test "$(mode "$R/etc/fastrdp/proxy.ini")" = 640
check "session postinst without fastrdp-xrdp" run "$R" fastrdp-session.postinst configure
check "no /etc/xrdp without fastrdp-xrdp" test ! -e "$R/etc/xrdp"
xrdp_payload "$R"
xrdp_postinst "$R"
check "session trigger after fastrdp-xrdp" run "$R" fastrdp-session.postinst triggered "$UP"
for f in /etc/xrdp/xrdp.ini /etc/xrdp/sesman.ini /etc/xrdp/gfx.toml /etc/X11/xrdp/xorg.conf; do
    check "$f: fastrdp's version replaced upstream's" cmp "$R$f" "$REPO/packaging/defaults/fastrdp-session$f"
done
check "startwm.sh: fastrdp's, executable" bash -c 'cmp "$1/etc/xrdp/startwm.sh" "$2" && test -x "$1/etc/xrdp/startwm.sh"' \
    _ "$R" "$REPO/broker/session/libexec/startwm.sh"
check "xrdp-sesman PAM: token-only stack" cmp "$R/etc/pam.d/xrdp-sesman" "$REPO/broker/session/pam/xrdp-sesman"

# --- the other order: fastrdp-session first, fastrdp-xrdp's postinst keeps its files
R2=$T/b
payload "$R2"
xrdp_payload "$R2"
check "session postinst with fastrdp-xrdp unpacked" run "$R2" fastrdp-session.postinst configure
xrdp_postinst "$R2"
check "xrdp.ini stays fastrdp's" cmp "$R2/etc/xrdp/xrdp.ini" "$REPO/packaging/defaults/fastrdp-session/etc/xrdp/xrdp.ini"

# --- upgrade: a new default replaces unchanged files only
check "status" env DPKG_ROOT="$R" "$R/usr/sbin/fastrdp-defaults" status
output_has "status: broker.toml is the default" "/etc/fastrdp/broker.toml +fastrdp default"
echo "# admin" >> "$R/etc/xrdp/sesman.ini"
for f in xrdp.ini sesman.ini; do echo "; fastrdp 2" >> "$R/usr/share/fastrdp-session/defaults/etc/xrdp/$f"; done
check "session postinst on upgrade" run "$R" fastrdp-session.postinst configure 1.0
output_has "unchanged xrdp.ini updated" "updated /etc/xrdp/xrdp.ini"
output_has "changed sesman.ini kept, with a pointer" "kept /etc/xrdp/sesman.ini \(changed locally\).*fastrdp-defaults diff"
check "xrdp.ini is the new default" cmp "$R/etc/xrdp/xrdp.ini" "$R/usr/share/fastrdp-session/defaults/etc/xrdp/xrdp.ini"
check "sesman.ini keeps the admin's line" grep -qx "# admin" "$R/etc/xrdp/sesman.ini"
check "same version again" run "$R" fastrdp-session.postinst configure 1.0
output_lacks "the note comes once per new default" "kept /etc/xrdp/sesman.ini"
check "diff" env DPKG_ROOT="$R" "$R/usr/sbin/fastrdp-defaults" diff /etc/xrdp/sesman.ini
output_has "diff shows the admin's line" "^\+# admin"
output_lacks "diff only for the named file" "xrdp.ini"
check "status after the change" env DPKG_ROOT="$R" "$R/usr/sbin/fastrdp-defaults" status fastrdp-session
output_has "status: sesman.ini changed" "/etc/xrdp/sesman.ini +changed locally"

# --- a file written by Ansible before the package: kept, never ours
R3=$T/c
payload "$R3"
mkdir -p "$R3/etc/fastrdp"
echo "# Ansible managed" > "$R3/etc/fastrdp/broker.toml"
check "broker postinst over an Ansible file" run "$R3" fastrdp-broker.postinst configure
output_has "Ansible file kept" "kept /etc/fastrdp/broker.toml"
check "Ansible file unchanged" grep -qx "# Ansible managed" "$R3/etc/fastrdp/broker.toml"
check "purge" run "$R3" fastrdp-broker.postrm purge
check "purge keeps a file that was never ours" test -f "$R3/etc/fastrdp/broker.toml"

# --- purge removes unchanged files only
check "session purge" run "$R" fastrdp-session.postrm purge
check "purge removed unchanged xrdp.ini" test ! -e "$R/etc/xrdp/xrdp.ini"
check "purge kept changed sesman.ini" test -f "$R/etc/xrdp/sesman.ini"
check "purge removed the state" test ! -e "$R/var/lib/fastrdp/defaults/fastrdp-session"
check "broker purge" run "$R" fastrdp-broker.postrm purge
check "broker.toml removed" test ! -e "$R/etc/fastrdp/broker.toml"

# --- fastrdp-server: nftables and Kerberos snippets; the sssd one only with sssd
R4=$T/d
payload "$R4"
check "server postinst" run "$R4" fastrdp-server.postinst configure
check "nftables table installed" test -f "$R4/etc/nftables.d/fastrdp.nft"
check "krb5 snippet installed" test -f "$R4/etc/krb5.conf.d/fastrdp"
check "no sssd snippet without sssd" test ! -e "$R4/etc/sssd/conf.d/50-fastrdp.conf"
mkdir -p "$R4/usr/sbin" && : > "$R4/usr/sbin/sssd"
check "server trigger after sssd" run "$R4" fastrdp-server.postinst triggered /usr/sbin/sssd
check "sssd snippet 0600" test "$(mode "$R4/etc/sssd/conf.d/50-fastrdp.conf")" = 600

# --- fastrdp-archive-keyring: APT source unless one exists, removed on purge if ours
R5=$T/e
mkdir -p "$R5/etc/apt/sources.list.d"
printf 'ID=debian\nVERSION_CODENAME=trixie\n' > "$R5/etc/os-release"
check "keyring postinst" run "$R5" fastrdp-archive-keyring.postinst configure
S=$R5/etc/apt/sources.list.d/fast-rdp-server.sources
check "sources: trixie-stable" grep -qx "Suites: trixie-stable" "$S"
check "sources: packaged key" grep -qx "Signed-By: /usr/share/keyrings/fast-rdp-server-archive-keyring.asc" "$S"
check "keyring purge" run "$R5" fastrdp-archive-keyring.postrm purge
check "own sources file removed" test ! -e "$S"
echo "deb [signed-by=/x] https://linuxrrze.github.io/fast-rdp-server trixie-stable main" > "$R5/etc/apt/sources.list.d/own.list"
check "keyring postinst with an own source" run "$R5" fastrdp-archive-keyring.postinst configure
check "no second source" test ! -e "$S"
rm "$R5/etc/apt/sources.list.d/own.list"
printf 'ID=ubuntu\nVERSION_CODENAME=noble\n' > "$R5/etc/os-release"
check "keyring postinst on an unsupported release" run "$R5" fastrdp-archive-keyring.postinst configure
output_has "says why" "no packages for 'noble'"
check "packaged key is the repository's signing key" \
    bash -c 'command -v gpg >/dev/null || exit 0
             gpg --show-keys --with-colons "$1" | grep -q "^fpr:::::::::D226CF9C3D771BBE86746D88F7930BCDA7F642DD:"' \
    _ "$REPO/packaging/apt/fast-rdp-server-archive-keyring.asc"
finish

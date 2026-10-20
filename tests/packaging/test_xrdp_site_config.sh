#!/bin/bash
# shellcheck disable=SC2016  # the fake install scripts are written literally
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# third_party/build-xrdp.sh and the fastrdp-xrdp maintainer scripts: the site
# configuration (xrdp.ini, sesman.ini, gfx.toml, startwm.sh, xorg.conf, PAM stack) is
# never a conffile and never overwritten. Fake autoreconf/configure/make install
# upstream-like trees; postinst/postrm run against a DPKG_ROOT.
set -euo pipefail
# shellcheck source=tests/lib.sh
. "$(dirname "$0")/../lib.sh"
need sed cmp find

SITE="/etc/xrdp/xrdp.ini /etc/xrdp/sesman.ini /etc/xrdp/gfx.toml /etc/xrdp/startwm.sh
/etc/X11/xrdp/xorg.conf /etc/pam.d/xrdp-sesman"
DEF=/usr/share/fastrdp-xrdp/default-config

# --- fake toolchain: `make install DESTDIR=D` runs ./fake-install.sh D in the tree
mkdir -p "$T/bin"
printf '#!/bin/sh\nexit 0\n' > "$T/bin/autoreconf"
cat > "$T/bin/make" <<'EOF'
#!/bin/sh
dest=
for a; do case $a in DESTDIR=*) dest=${a#DESTDIR=} ;; esac; done
for a; do [ "$a" = install ] && exec ./fake-install.sh "$dest"; done
exit 0
EOF
chmod +x "$T/bin/autoreconf" "$T/bin/make"
export PATH="$T/bin:$PATH"

mk_tree() {   # mk_tree DIR INSTALL-SCRIPT-BODY
    mkdir -p "$1"
    printf '#!/bin/sh\nexit 0\n' > "$1/configure"
    printf '#!/bin/sh\nset -e\nd=$1\n%s\n' "$2" > "$1/fake-install.sh"
    chmod +x "$1/configure" "$1/fake-install.sh"
}
# xrdp: sbin/xrdp, xrdp.pc, its /etc files (startwm.sh executable), PAM stack
XRDP_INSTALL='mkdir -p "$d/usr/sbin" "$d/usr/lib/pkgconfig" "$d/etc/xrdp" "$d/etc/pam.d"
echo bin > "$d/usr/sbin/xrdp"
echo "prefix=/usr" > "$d/usr/lib/pkgconfig/xrdp.pc"
for f in xrdp.ini sesman.ini gfx.toml km-00000407.ini; do echo "upstream $f" > "$d/etc/xrdp/$f"; done
echo "upstream startwm.sh" > "$d/etc/xrdp/startwm.sh"; chmod 0755 "$d/etc/xrdp/startwm.sh"
echo "upstream pam" > "$d/etc/pam.d/xrdp-sesman"
[ -z "${FAKE_FAIL_XRDP:-}" ] || exit 1'
XORG_INSTALL='mkdir -p "$d/usr/lib/xorg/modules/drivers" "$d/etc/X11/xrdp"
echo upstream > "$d/etc/X11/xrdp/xorg.conf"
[ -z "${FAKE_FAIL_XORG:-}" ] || exit 1
echo so > "$d/usr/lib/xorg/modules/drivers/xrdpdev_drv.so"'
mk_tree "$T/xrdp" "$XRDP_INSTALL"
mk_tree "$T/xorgxrdp" "$XORG_INSTALL"
echo '#define XRDP_CONFIGURE_OPTIONS "--enable-x264 --enable-ffmpeg"' > "$T/xrdp/xrdp_configure_options.h"
build() { JOBS=1 "$REPO/third_party/build-xrdp.sh" "$T/xrdp" "$T/xorgxrdp" "$1"; }

# --- 1. packaging (empty DESTDIR): defaults only, nothing site-specific under /etc
D=$T/pkg
check "build into an empty DESTDIR" build "$D"
for f in $SITE; do
    check "$f: not installed (no conffile)" test ! -e "$D$f"
    check "$f: upstream version in $DEF" grep -q upstream "$D$DEF$f"
done
check "default startwm.sh stays executable" test -x "$D$DEF/etc/xrdp/startwm.sh"
check "other /etc files still installed (km-*.ini)" test -f "$D/etc/xrdp/km-00000407.ini"

# --- 2. existing site configuration (the Ansible build on a configured host): kept
H=$T/host
mkdir -p "$H/etc/xrdp" "$H/etc/X11/xrdp" "$H/etc/pam.d"
for f in $SITE; do echo "site $f" > "$H$f"; done
chmod 0755 "$H/etc/xrdp/startwm.sh"
chmod 0640 "$H/etc/xrdp/sesman.ini"
check "rebuild over a configured tree" build "$H"
for f in $SITE; do
    check "$f: site version kept" grep -qx "site $f" "$H$f"
    check "$f: upstream version in $DEF" grep -q upstream "$H$DEF$f"
done
check "site file modes kept" test "$(stat -c %a "$H/etc/xrdp/sesman.ini")" = 640
check "site startwm.sh still executable" test -x "$H/etc/xrdp/startwm.sh"

# --- 3. a failed install restores the site files it may have overwritten
F=$T/fail
mkdir -p "$F/etc/xrdp" "$F/etc/X11/xrdp" "$F/etc/pam.d"
for f in $SITE; do echo "site $f" > "$F$f"; done
FAKE_FAIL_XORG=1 expect_exit nonzero "failing xorgxrdp install fails the build" build "$F"
for f in $SITE; do check "$f: restored after the failure" grep -qx "site $f" "$F$f"; done

# --- 4. a site file that make install no longer creates is an error (list out of date)
sed -i '/xrdp-sesman/d' "$T/xrdp/fake-install.sh"
expect_exit nonzero "missing site file from make install fails" build "$T/nopam"
output_has "names the missing file" "did not create /etc/pam.d/xrdp-sesman"

# --- 5. fastrdp-xrdp postinst/postrm (DPKG_ROOT): defaults only where a file is missing
P=$REPO/packaging/xrdp/debian
R=$T/root
mkdir -p "$R"
cp -a "$D/usr" "$R/"
mkdir -p "$R/etc/xrdp"
echo "admin" > "$R/etc/xrdp/xrdp.ini"   # e.g. an obsolete conffile of -1, or the role's file
touch "$R/etc/xrdp/cert.pem" "$R/etc/xrdp/key.pem" "$R/etc/xrdp/rsakeys.ini"   # no openssl/chown
check "postinst configure" env DPKG_ROOT="$R" sh "$P/fastrdp-xrdp.postinst" configure ""
check "existing xrdp.ini untouched" grep -qx admin "$R/etc/xrdp/xrdp.ini"
for f in $SITE; do
    [ "$f" = /etc/xrdp/xrdp.ini ] && continue
    check "$f: created from the default" cmp "$R$DEF$f" "$R$f"
done
check "startwm.sh created executable" test -x "$R/etc/xrdp/startwm.sh"
echo "changed" > "$R/etc/xrdp/gfx.toml"
check "postinst on upgrade" env DPKG_ROOT="$R" sh "$P/fastrdp-xrdp.postinst" configure 0.10.6.1+xorgxrdp0.10.5-1
check "changed gfx.toml kept on upgrade" grep -qx changed "$R/etc/xrdp/gfx.toml"
check "postrm remove keeps the configuration" env DPKG_ROOT="$R" sh "$P/fastrdp-xrdp.postrm" remove
check "xrdp.ini still there after remove" test -f "$R/etc/xrdp/xrdp.ini"
check "postrm purge" env DPKG_ROOT="$R" sh "$P/fastrdp-xrdp.postrm" purge
for f in $SITE; do check "$f: removed on purge" test ! -e "$R$f"; done
# (that the installed package has no such conffiles: tests/packaging/check-installed.sh)
finish

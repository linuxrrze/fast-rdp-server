# shellcheck shell=bash disable=SC2034  # PROXY/INC/LNK are used by the sourcing script
# Sourced by the e2e scripts after SYSROOT and LIBDIR are set. Chooses which FreeRDP the
# tests build against and run:
#   default          the system / SYSROOT freerdp3 (distribution packages)
#   FREERDP_PREFIX   fastrdp's patched build (third_party/build-freerdp.sh), e.g.
#                    /opt/fastrdp or a DESTDIR staging copy of it
# Sets PROXY, INC and LNK.
FREERDP_PREFIX=${FREERDP_PREFIX:-}
if [ -n "$FREERDP_PREFIX" ]; then
    PROXY=${PROXY:-$FREERDP_PREFIX/bin/freerdp-proxy}
    INC=(-I"$FREERDP_PREFIX/include/freerdp3" -I"$FREERDP_PREFIX/include/winpr3" -I"$SYSROOT/usr/include")
    # DT_RPATH (not RUNPATH): LD_LIBRARY_PATH below also lists the distro freerdp3
    LNK=(-L"$FREERDP_PREFIX/lib" "-Wl,--disable-new-dtags" "-Wl,-rpath,$FREERDP_PREFIX/lib" -L"$LIBDIR"
         "-Wl,-rpath-link,$FREERDP_PREFIX/lib:$LIBDIR:$LIBDIR/pulseaudio")
else
    PROXY=${PROXY:-$SYSROOT/usr/bin/freerdp-proxy}
    INC=(-I"$SYSROOT/usr/include/freerdp3" -I"$SYSROOT/usr/include/winpr3" -I"$SYSROOT/usr/include")
    LNK=(-L"$LIBDIR" "-Wl,-rpath-link,$LIBDIR:$LIBDIR/pulseaudio")
fi
echo "e2e: FreeRDP from ${FREERDP_PREFIX:-${SYSROOT:-system}} ($PROXY)" >&2

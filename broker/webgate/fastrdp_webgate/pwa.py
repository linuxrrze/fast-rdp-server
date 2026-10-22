# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Files of the notification opt-in page (docs/notifications.md): the service worker,
the page's script, the web app manifest and icons (home screen web app, which iOS needs
for Web Push), and the QR code of the user's ntfy topic.

Static files come from the package's static/ directory; the PNG icons are drawn here
(stdlib zlib) so the package carries no binary files. The QR code reuses the broker's
encoder (fastrdp_broker.qrcode, the same one that draws the waiting screen's code):
fastrdp-webgate depends on fastrdp-broker, which installs it next to this package."""

from __future__ import annotations

import functools
import json
import struct
import zlib
from pathlib import Path

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC = {
    "notify.js": "text/javascript; charset=utf-8",
    "icon.svg": "image/svg+xml",
}
BLUE, WHITE = (0x1D, 0x4E, 0xD8), (0xFF, 0xFF, 0xFF)
# icon.svg on its 64 x 64 grid: (x, y, width, height, colour), drawn in order
ICON_RECTS = ((10, 14, 44, 28, WHITE), (14, 18, 36, 20, BLUE), (28, 42, 8, 6, WHITE), (20, 48, 24, 4, WHITE))
ICON_SIZES = (192, 512)


def static_file(name: str) -> tuple[bytes, str] | None:
    """(content, content type) of a file under <prefix>/static/, or None."""
    if name in STATIC or name in (f"icon-{size}.png" for size in ICON_SIZES):
        return _static(name)   # cached for known names only
    return None


@functools.cache
def _static(name: str) -> tuple[bytes, str]:
    if name in STATIC:
        return (STATIC_DIR / name).read_bytes(), STATIC[name]
    return png_icon(int(name[len("icon-"):-len(".png")])), "image/png"


@functools.cache
def service_worker() -> bytes:
    return (STATIC_DIR / "sw.js").read_bytes()


def _png(width: int, height: int, rows: list[bytes]) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack("!I", len(data)) + kind + data + struct.pack("!I", zlib.crc32(kind + data))
    raw = b"".join(b"\0" + row for row in rows)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack("!IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def png_icon(size: int) -> bytes:
    """icon.svg as an opaque square PNG (home screens round the corners themselves)."""
    grid = [[BLUE] * 64 for _ in range(64)]
    for x0, y0, w, h, colour in ICON_RECTS:
        for y in range(y0, y0 + h):
            for x in range(x0, x0 + w):
                grid[y][x] = colour
    rows = [b"".join(bytes(grid[y * 64 // size][x * 64 // size]) for x in range(size)) for y in range(size)]
    return _png(size, size, rows)


def manifest(prefix: str) -> bytes:
    """Web app manifest: "Add to Home Screen" opens the opt-in page as an app."""
    icons = [{"src": f"{prefix}/static/icon.svg", "sizes": "any", "type": "image/svg+xml"}]
    icons += [{"src": f"{prefix}/static/icon-{s}.png", "sizes": f"{s}x{s}", "type": "image/png"}
              for s in ICON_SIZES]
    return json.dumps({
        "name": "fastrdp login approval", "short_name": "fastrdp",
        "start_url": f"{prefix}/notify", "scope": f"{prefix}/", "display": "standalone",
        "background_color": "#ffffff", "theme_color": "#1d4ed8", "icons": icons,
    }, indent=1).encode()


def _qr_encoder():
    try:
        from fastrdp_broker import qrcode
    except ImportError:  # a webgate without the broker package: the page shows the URL only
        return None
    return qrcode


def qr_svg(text: str, max_version: int = 10) -> str | None:
    """Inline SVG of a QR code of `text` (4 modules quiet zone); None without the
    encoder or if the text does not fit."""
    qrcode = _qr_encoder()
    if qrcode is None:
        return None
    try:
        rows = qrcode.encode(text.encode(), max_version)
    except ValueError:
        return None
    n = len(rows) + 8
    path = "".join(f"M{x + 4},{y + 4}h1v1h-1z" for y, row in enumerate(rows) for x, c in enumerate(row) if c == "1")
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n} {n}" width="220" height="220" '
            f'role="img" aria-label="QR code"><rect width="{n}" height="{n}" fill="#fff"/>'
            f'<path d="{path}" fill="#000"/></svg>')

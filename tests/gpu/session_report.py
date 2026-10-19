#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Which GPU paths does this remote session really use?

Run inside a fastrdp session (any back-end) as the session user:

    python3 tests/gpu/session_report.py            # human-readable
    python3 tests/gpu/session_report.py --json     # for tests/perf/results

Evidence comes from /proc: render nodes opened and encoder libraries mapped by the
processes that draw (Xorg, gnome-shell, kwin_wayland) and encode (xrdp,
gnome-remote-desktop, krdpserver). Tool output (glxinfo, vulkaninfo, vainfo) is
added when the tools are installed. No root needed for the user's own processes;
Xorg (xrdp sessions) runs as the user too.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

RENDERERS = ("Xorg", "gnome-shell", "kwin_wayland", "Xwayland", "sway", "labwc", "wayfire")
ENCODERS = ("xrdp", "gnome-remote-d", "gnome-remote-desktop-daemon", "krdpserver")

# library substring -> meaning
LIB_HINTS = {
    "libnvidia-encode": "nvenc",
    "libcuda": "cuda",
    "libva.so": "vaapi",
    "libva-drm": "vaapi",
    "libvulkan": "vulkan",
    "libx264": "x264",
    "libopenh264": "openh264",
    "libnvidia-glcore": "nvidia-gl",
    "radeonsi": "mesa-radeonsi",
    "iris_dri": "mesa-iris",
    "libgallium": "mesa-gallium",
    "swrast": "software-gl",
    "llvmpipe": "software-gl",
}


def proc_comm(pid: str, root: str) -> str:
    try:
        with open(f"{root}/{pid}/comm", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def proc_uid(pid: str, root: str) -> int:
    try:
        with open(f"{root}/{pid}/status", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("Uid:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return -1


def open_devices(pid: str, root: str) -> set[str]:
    out = set()
    fd_dir = f"{root}/{pid}/fd"
    try:
        for fd in os.listdir(fd_dir):
            try:
                target = os.readlink(f"{fd_dir}/{fd}")
            except OSError:
                continue
            if target.startswith("/dev/dri/") or target.startswith("/dev/nvidia"):
                out.add(target)
    except OSError:
        pass
    return out


def mapped_hints(pid: str, root: str) -> set[str] | None:
    """Library hints from /proc/<pid>/maps; None if not readable (other user's process)."""
    hints = set()
    try:
        with open(f"{root}/{pid}/maps", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                path = line.rsplit(" ", 1)[-1]
                for needle, meaning in LIB_HINTS.items():
                    if needle in path:
                        hints.add(meaning)
    except PermissionError:
        return None
    except OSError:
        pass
    return hints


def scan(uid: int, root: str = "/proc") -> list[dict]:
    rows = []
    for pid in os.listdir(root):
        if not pid.isdigit():
            continue
        comm = proc_comm(pid, root)
        role = "render" if comm in RENDERERS else "encode" if comm in ENCODERS else None
        if role is None:
            continue
        owner = proc_uid(pid, root)
        if owner not in (uid, 0) and comm != "xrdp":
            continue
        rows.append({
            "pid": int(pid),
            "process": comm,
            "role": role,
            "uid": owner,
            "devices": sorted(open_devices(pid, root)),
            "libraries": None if (h := mapped_hints(pid, root)) is None else sorted(h),
        })
    return sorted(rows, key=lambda r: (r["role"], r["process"], r["pid"]))


def verdict(rows: list[dict]) -> dict:
    """Summarise rendering and encoding paths from the process evidence."""
    render, encode = "unknown", "unknown"
    xrdp_verdicts = []
    for r in rows:
        libs, devs = set(r["libraries"] or []), r["devices"]
        if r["role"] == "render":
            if "nvidia-gl" in libs or any(d.startswith("/dev/nvidia") for d in devs):
                render = "gpu (nvidia)"
            elif any("renderD" in d or "card" in d for d in devs):
                render = "gpu (mesa)" if render == "unknown" else render
            elif "software-gl" in libs and render == "unknown":
                render = "software (llvmpipe)"
        else:
            if r["process"] == "xrdp":
                # xrdp encodes in its own (unprivileged, uid xrdp) processes, one per
                # connection and shared by all users: x264, or the fastrdp FFmpeg backend
                # with VA-API/NVENC/QSV. Which one serves this session is not visible here.
                if r["libraries"] is None:
                    xrdp_verdicts.append("xrdp: not readable as this user, see xrdp.log 'xrdp_encoder_ffmpeg: using'")
                elif "nvenc" in libs:
                    xrdp_verdicts.append("nvenc (gpu, xrdp ffmpeg)")
                elif "vaapi" in libs and any("renderD" in d for d in devs):
                    xrdp_verdicts.append("vaapi (gpu, xrdp ffmpeg)")
                else:
                    xrdp_verdicts.append("x264 (cpu)")
            elif "nvenc" in libs:
                encode = "nvenc (gpu)"
            elif "vaapi" in libs and any("renderD" in d for d in devs):
                encode = "vaapi (gpu)"
            elif "x264" in libs:
                encode = "x264 (cpu)"
            elif "openh264" in libs:
                encode = "openh264 (cpu)"
            elif encode == "unknown":
                encode = "no h264 encoder loaded (rfx/progressive)"
    if xrdp_verdicts:
        kinds = sorted(set(xrdp_verdicts))
        encode = kinds[0] if len(kinds) == 1 else (
            "differs between xrdp processes (other users' sessions included): " + "; ".join(kinds))
    return {"rendering": render, "h264_encoding": encode}


def tool(cmd: list[str], pattern: str) -> list[str]:
    if not shutil.which(cmd[0]):
        return []
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [line.strip() for line in out.splitlines() if re.search(pattern, line)]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--proc", default="/proc", help=argparse.SUPPRESS)
    args = ap.parse_args()

    rows = scan(os.getuid(), args.proc)
    report = {
        "session_type": os.environ.get("XDG_SESSION_TYPE", ""),
        "desktop": os.environ.get("XDG_CURRENT_DESKTOP", ""),
        "processes": rows,
        "verdict": verdict(rows),
        "gl_renderer": tool(["glxinfo", "-B"], r"OpenGL renderer|Accelerated"),
        "vulkan_devices": tool(["vulkaninfo", "--summary"], r"deviceName|deviceType"),
        "vaapi_h264_encode": tool(["vainfo"], r"VAProfileH264.*VAEntrypointEnc"),
        "nvenc_sessions": tool(["nvidia-smi", "--query-gpu=name,encoder.stats.sessionCount",
                                "--format=csv,noheader"], r"."),
    }
    if args.json:
        json.dump(report, sys.stdout, indent=2)
        print()
        return 0

    print(f"session: {report['session_type'] or '?'} / {report['desktop'] or '?'}")
    print(f"rendering:     {report['verdict']['rendering']}")
    print(f"H.264 encoder: {report['verdict']['h264_encoding']}")
    for r in rows:
        print(f"  {r['role']:6} {r['process']:<28} pid {r['pid']:<7} "
              f"dev={','.join(r['devices']) or '-'} "
              f"libs={'(not readable)' if r['libraries'] is None else ','.join(r['libraries']) or '-'}")
    for key in ("gl_renderer", "vulkan_devices", "vaapi_h264_encode", "nvenc_sessions"):
        for line in report[key]:
            print(f"  {key}: {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Fixture tests for session_report (fake /proc trees)."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import session_report  # noqa: E402

UID = os.getuid()


def fake_proc(root, pid, comm, uid=UID, devices=(), libs=()):
    d = os.path.join(root, str(pid))
    os.makedirs(os.path.join(d, "fd"))
    with open(os.path.join(d, "comm"), "w") as fh:
        fh.write(comm + "\n")
    with open(os.path.join(d, "status"), "w") as fh:
        fh.write(f"Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    for i, dev in enumerate(devices):
        os.symlink(dev, os.path.join(d, "fd", str(10 + i)))
    with open(os.path.join(d, "maps"), "w") as fh:
        for lib in libs:
            fh.write(f"7f0000000000-7f0000001000 r-xp 00000000 08:01 1 {lib}\n")


class VerdictTests(unittest.TestCase):
    def run_scan(self, *procs):
        with tempfile.TemporaryDirectory() as root:
            for p in procs:
                fake_proc(root, **p)
            rows = session_report.scan(UID, root)
            return rows, session_report.verdict(rows)

    def test_gnome_vaapi(self):
        rows, v = self.run_scan(
            dict(pid=10, comm="gnome-shell", devices=["/dev/dri/renderD128"],
                 libs=["/usr/lib/x86_64-linux-gnu/libgallium-25.so"]),
            dict(pid=11, comm="gnome-remote-d", devices=["/dev/dri/renderD128"],
                 libs=["/usr/lib/x86_64-linux-gnu/libva.so.2", "/usr/lib/libvulkan.so.1"]),
        )
        self.assertEqual(v, {"rendering": "gpu (mesa)", "h264_encoding": "vaapi (gpu)"})

    def test_gnome_nvenc(self):
        _, v = self.run_scan(
            dict(pid=20, comm="gnome-shell", devices=["/dev/nvidia0", "/dev/dri/card1"],
                 libs=["/usr/lib/libnvidia-glcore.so.570"]),
            dict(pid=21, comm="gnome-remote-d",
                 libs=["/usr/lib/libcuda.so.1", "/usr/lib/libnvidia-encode.so.1"]),
        )
        self.assertEqual(v, {"rendering": "gpu (nvidia)", "h264_encoding": "nvenc (gpu)"})

    def test_plasma_on_nvidia_falls_back_to_x264(self):
        _, v = self.run_scan(
            dict(pid=30, comm="kwin_wayland", devices=["/dev/nvidia0"]),
            dict(pid=31, comm="krdpserver", libs=["/usr/lib/libx264.so.165"]),
        )
        self.assertEqual(v["h264_encoding"], "x264 (cpu)")

    def test_xrdp_software(self):
        rows, v = self.run_scan(
            dict(pid=40, comm="Xorg", libs=["/usr/lib/dri/swrast_dri.so"]),
            dict(pid=41, comm="xrdp", uid=999),  # unprivileged daemon user is still shown
        )
        self.assertEqual(v, {"rendering": "software (llvmpipe)", "h264_encoding": "x264 (cpu)"})
        self.assertEqual(len(rows), 2)

    def test_xrdp_vaapi_encoder(self):
        _, v = self.run_scan(
            dict(pid=60, comm="Xorg", devices=["/dev/dri/renderD128"]),
            dict(pid=61, comm="xrdp", uid=999, devices=["/dev/dri/renderD128"],
                 libs=["/usr/lib/libavcodec.so.62", "/usr/lib/x86_64-linux-gnu/libva.so.2"]),
        )
        self.assertEqual(v["h264_encoding"], "vaapi (gpu, xrdp ffmpeg)")

    def test_xrdp_unreadable(self):
        with tempfile.TemporaryDirectory() as root:
            fake_proc(root, 70, "xrdp", uid=999)
            os.chmod(os.path.join(root, "70", "maps"), 0)
            rows = session_report.scan(UID, root)
            if os.getuid() != 0:  # root can read anything
                self.assertIsNone(rows[0]["libraries"])
                self.assertIn("xrdp.log", session_report.verdict(rows)["h264_encoding"])

    def test_other_users_ignored(self):
        rows, _ = self.run_scan(dict(pid=50, comm="gnome-shell", uid=UID + 4242))
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()

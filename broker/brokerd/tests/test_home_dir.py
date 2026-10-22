# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""The user's home directory before any back-end starts (home.py, [broker] home_check).

Regression: an AD user's unixHomeDirectory was /autofs/srv/home/<user> on a host
without autofs. GNOME (no pam_mkhomedir) failed inside grdctl ("Error creating
directory /autofs: Permission denied", assertion) and the log only had the raw
grdctl output. Now the broker refuses with a line naming the missing parent, and
creates a missing home only when just its last component is missing.
"""

import asyncio
import errno
import os
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from fastrdp_broker import config, home, sysutil
from fastrdp_broker.backends import Target
from fastrdp_broker.identity import LocalUser
from test_server import ME, make_cfg, request

AUTOFS_MOUNTINFO = (
    "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
    "40 22 0:35 / {root} rw,relatime shared:20 - autofs systemd-1 rw,fd=50\n"
)


def user(home_dir: str, uid: int = ME.pw_uid, name: str = "marcel") -> LocalUser:
    return LocalUser(name, uid, ME.pw_gid, home_dir, frozenset({"rdp-users"}))


def root_owned(real_stat):
    """os.stat as if every directory were root-owned 0755 (tests run unprivileged)."""
    def fake(path, *a, **kw):
        st = real_stat(path, *a, **kw)
        values = list(st)
        values[4] = 0                                  # st_uid
        values[0] = (st.st_mode & ~0o7777) | 0o755     # st_mode
        return os.stat_result(values)
    return fake


class InspectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.mountinfo = os.path.join(self.root, "mountinfo")
        Path(self.mountinfo).write_text("")

    def tearDown(self):
        self.tmp.cleanup()

    def inspect(self, path):
        return home.inspect(path, self.mountinfo)

    def test_existing_directory(self):
        d = os.path.join(self.root, "alice")
        os.mkdir(d)
        ins = self.inspect(d + "/")
        self.assertEqual((ins.state, ins.path, ins.uid), ("ok", d, ME.pw_uid))

    def test_stat_with_trailing_slash_mounts_browse_placeholders(self):
        # autofs browse mode: lstat sees a root-owned placeholder; "<home>/" mounts it
        d = os.path.join(self.root, "alice")
        os.mkdir(d)
        real = os.stat

        def fake(path, *a, **kw):
            if path == d + "/":
                raise FileNotFoundError(errno.ENOENT, "No such file or directory")
            return real(path, *a, **kw)

        with mock.patch("fastrdp_broker.home.os.stat", side_effect=fake):
            ins = self.inspect(d)
        self.assertEqual(ins.state, "bad")
        self.assertIn("cannot be mounted", ins.detail)

    def test_symlink_to_directory_is_fine(self):
        d = os.path.join(self.root, "data")
        os.mkdir(d)
        os.symlink(d, os.path.join(self.root, "alice"))
        self.assertEqual(self.inspect(os.path.join(self.root, "alice")).state, "ok")

    def test_only_last_component_missing(self):
        ins = self.inspect(os.path.join(self.root, "alice"))
        self.assertEqual((ins.state, ins.parent), ("missing", self.root))

    def test_missing_automount_root(self):
        path = os.path.join(self.root, "autofs/srv/home/marcel")
        ins = self.inspect(path)
        self.assertEqual(ins.state, "no_parent")
        self.assertEqual(ins.missing, os.path.join(self.root, "autofs"))
        self.assertEqual(ins.detail, f"parent {self.root}/autofs missing: automount not set up?")

    def test_missing_below_an_automount_point(self):
        Path(self.mountinfo).write_text(AUTOFS_MOUNTINFO.format(root=self.root))
        ins = self.inspect(os.path.join(self.root, "srv/marcel"))
        self.assertEqual(ins.state, "no_parent")
        self.assertIn(f"below the automount point {self.root}: no map entry", ins.detail)

    def test_not_a_directory(self):
        f = os.path.join(self.root, "alice")
        Path(f).write_text("x")
        self.assertEqual(self.inspect(f).state, "bad")
        self.assertEqual(self.inspect(os.path.join(f, "sub")).state, "bad")

    def test_dangling_symlink_is_refused(self):
        link = os.path.join(self.root, "alice")
        os.symlink(os.path.join(self.root, "elsewhere"), link)
        ins = self.inspect(link)
        self.assertEqual(ins.state, "bad")
        self.assertIn("symbolic link to a missing target", ins.detail)

    def test_odd_paths(self):
        for path in ("", "relative/home", "/", "/home/../etc", "//home/x"):
            with self.subTest(path=path):
                self.assertEqual(self.inspect(path).state, "bad")

    def test_root_cannot_look(self):
        # Kerberized NFS / root_squash: unknown, never refused
        for code in (errno.EACCES, errno.EPERM, errno.EKEYEXPIRED, errno.ESTALE):
            with self.subTest(errno=errno.errorcode[code]), \
                    mock.patch("fastrdp_broker.home.os.lstat", side_effect=OSError(code, os.strerror(code))):
                self.assertEqual(self.inspect("/nfs/home/alice").state, "unknown")

    def test_mountinfo_escapes(self):
        Path(self.mountinfo).write_text(AUTOFS_MOUNTINFO.format(root="/mnt/with\\040space"))
        self.assertEqual(home.autofs_mounts(self.mountinfo), {"/mnt/with space"})
        self.assertEqual(home.autofs_mounts(os.path.join(self.root, "none")), set())


class CreationRefusalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.parent = os.path.join(self.tmp.name, "home")
        os.mkdir(self.parent, 0o755)
        self.mountinfo = os.path.join(self.tmp.name, "mountinfo")
        Path(self.mountinfo).write_text("")

    def tearDown(self):
        self.tmp.cleanup()

    def test_root_owned_parent_allows_creation(self):
        with mock.patch("fastrdp_broker.home.os.stat", side_effect=root_owned(os.stat)):
            self.assertIsNone(home.creation_refusal(self.parent, [self.tmp.name], self.mountinfo))

    @unittest.skipIf(os.geteuid() == 0, "the directories belong to root then")
    def test_parent_owned_by_a_user(self):
        # a user who owns a path component could swap the home for a symlink
        reason = home.creation_refusal(self.parent, [self.tmp.name], self.mountinfo)
        self.assertRegex(reason, "is not a directory owned and writable only by root")

    def test_writable_by_others(self):
        real = root_owned(os.stat)

        def fake(path, *a, **kw):
            st = real(path, *a, **kw)
            if path == self.parent:
                values = list(st)
                values[0] = st.st_mode | 0o1777  # like /tmp
                return os.stat_result(values)
            return st

        with mock.patch("fastrdp_broker.home.os.stat", side_effect=fake):
            self.assertEqual(home.creation_refusal(self.parent, [self.tmp.name], self.mountinfo),
                             f"{self.parent} is not a directory owned and writable only by root")

    def refusal(self, parent, roots):
        with mock.patch("fastrdp_broker.home.os.stat", side_effect=root_owned(os.stat)):
            return home.creation_refusal(parent, roots, self.mountinfo)

    def test_create_roots(self):
        # parent = a root, or below one (/home/%d/%u)
        self.assertIsNone(self.refusal(self.parent, [self.parent]))
        sub = os.path.join(self.parent, "example.com")
        os.mkdir(sub)
        self.assertIsNone(self.refusal(sub, [self.parent, "/srv/homes"]))
        # outside every root; a name that only starts like a root
        other = os.path.join(self.tmp.name, "home2")
        os.mkdir(other)
        self.assertEqual(self.refusal(other, [self.parent]),
                         f"{other} is not below [broker] home_create_roots ({self.parent})")
        self.assertIn("is not below", self.refusal(self.tmp.name, [self.parent]))
        # empty list: never create
        self.assertEqual(self.refusal(self.parent, []),
                         "[broker] home_create_roots is empty (homes are provisioned elsewhere)")

    def test_create_roots_and_symlinks(self):
        real = os.path.join(self.tmp.name, "var-home")
        os.mkdir(real)
        link = os.path.join(self.tmp.name, "linked-home")
        os.symlink(real, link)
        # the root itself is a symlink (/home -> /var/home): fine
        self.assertIsNone(self.refusal(link, [link]))
        # a symlink below a root that leads out of it: refused
        outside = os.path.join(self.tmp.name, "elsewhere")
        os.mkdir(outside)
        escape = os.path.join(self.parent, "escape")
        os.symlink(outside, escape)
        reason = self.refusal(escape, [self.parent])
        self.assertIn(f"{escape} is not below [broker] home_create_roots", reason)
        self.assertIn(f"it resolves to {os.path.realpath(outside)}", reason)

    def test_root_on_a_network_file_system(self):
        Path(self.mountinfo).write_text(
            "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
            f"41 22 0:36 / {self.parent} rw - nfs4 srv:/home rw\n")
        self.assertEqual(self.refusal(self.parent, [self.parent]),
                         f"{self.parent} is on nfs4: provision the home on the file server")

    def test_never_on_a_network_file_system(self):
        for fs in ("nfs4", "cifs", "fuse.sshfs"):
            with self.subTest(fs=fs):
                Path(self.mountinfo).write_text(
                    "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
                    f"41 22 0:36 / {self.tmp.name} rw - {fs} srv:/export rw\n")
                with mock.patch("fastrdp_broker.home.os.stat", side_effect=root_owned(os.stat)):
                    self.assertEqual(home.creation_refusal(self.parent, [self.tmp.name], self.mountinfo),
                                     f"{self.parent} is on {fs}: provision the home on the file server")
        self.assertEqual(home.fstype("/", self.mountinfo), "ext4")
        self.assertEqual(home.fstype(self.parent, self.mountinfo), "fuse.sshfs")

    def test_never_inside_an_automount_point(self):
        Path(self.mountinfo).write_text(AUTOFS_MOUNTINFO.format(root=self.parent))
        with mock.patch("fastrdp_broker.home.os.stat", side_effect=root_owned(os.stat)):
            self.assertIn("is an automount point", home.creation_refusal(self.parent, [self.tmp.name], self.mountinfo))


class PrepareTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.pool = ThreadPoolExecutor(max_workers=2)
        self.release = threading.Event()
        self.run = mock.AsyncMock(side_effect=self.fake_mkhomedir)
        self.patches = [mock.patch("fastrdp_broker.sysutil.run", self.run),
                        mock.patch("fastrdp_broker.home.MOUNTINFO", os.path.join(self.root, "none"))]
        for p in self.patches:
            p.start()

    async def asyncTearDown(self):
        self.release.set()
        for p in self.patches:
            p.stop()
        self.pool.shutdown(wait=True)
        self.tmp.cleanup()

    async def fake_mkhomedir(self, *argv, **kw):
        os.mkdir(self.user.home, 0o700)
        return sysutil.Result(0, "", "")

    async def prepare(self, mode="create", timeout=1.0):
        await home.prepare(self.user, mode, self.pool, timeout)

    async def test_missing_parent_refused_with_clear_message(self):
        self.user = user(os.path.join(self.root, "autofs/srv/home/marcel"))
        with self.assertRaises(home.HomeError) as cm:
            await self.prepare()
        self.assertEqual(str(cm.exception),
                         f"home directory {self.root}/autofs/srv/home/marcel of marcel does not exist "
                         f"(parent {self.root}/autofs missing: automount not set up?)")
        self.run.assert_not_called()  # never mkdir under a missing automount root
        self.assertFalse(os.path.exists(os.path.join(self.root, "autofs")))

    async def test_missing_home_created_like_pam_mkhomedir(self):
        self.user = user(os.path.join(self.root, "marcel"))
        with mock.patch("fastrdp_broker.home.creation_refusal", return_value=None), \
                self.assertLogs("fastrdp.home", "INFO") as logs:
            await self.prepare()
        self.run.assert_awaited_once()
        # outside the broker's ProtectHome=read-only sandbox (a transient system unit)
        self.assertEqual(self.run.call_args.args,
                         ("systemd-run", "--wait", "--pipe", "--quiet", "--collect", "--",
                          "mkhomedir_helper", "marcel", "0077", "/etc/skel", "0700"))
        self.assertNotIn("--user", self.run.call_args.args)
        self.assertIn("created home directory", "\n".join(logs.output))

    async def test_creation_refused_below_unsafe_parent(self):
        self.user = user(os.path.join(self.root, "marcel"))
        with mock.patch("fastrdp_broker.home.creation_refusal", return_value="/x is not ... root"), \
                self.assertRaisesRegex(home.HomeError, "does not exist, and the broker does not create it: /x"):
            await self.prepare()
        self.run.assert_not_called()

    async def test_create_roots_reach_the_refusal(self):
        self.user = user(os.path.join(self.root, "marcel"))
        with self.assertRaisesRegex(home.HomeError, r"home_create_roots is empty"):
            await home.prepare(self.user, "create", self.pool, 1.0, [])
        self.run.assert_not_called()
        # the parent is the configured root: created (directories faked root-owned)
        with mock.patch("fastrdp_broker.home.os.stat", side_effect=root_owned(os.stat)), \
                mock.patch("fastrdp_broker.sysutil.run_dropped", return_value=sysutil.Result(0, "", "")), \
                self.assertLogs("fastrdp.home", "INFO"):
            await home.prepare(self.user, "create", self.pool, 1.0, [self.root])
        self.run.assert_awaited_once()

    async def test_check_mode_never_creates(self):
        self.user = user(os.path.join(self.root, "marcel"))
        with self.assertRaisesRegex(home.HomeError, r"does not exist \(\[broker\] home_check = check"):
            await self.prepare("check")
        self.run.assert_not_called()

    async def test_mkhomedir_failure(self):
        self.user = user(os.path.join(self.root, "marcel"))
        self.run.side_effect = sysutil.CommandError("mkhomedir_helper marcel 0077 ... failed (13): Permission denied")
        with mock.patch("fastrdp_broker.home.creation_refusal", return_value=None), \
                self.assertRaisesRegex(home.HomeError, "could not be created: mkhomedir_helper .*Permission denied"):
            await self.prepare()

    async def test_off_touches_nothing(self):
        self.user = user(os.path.join(self.root, "autofs/marcel"))
        with mock.patch("fastrdp_broker.home.inspect") as insp:
            await self.prepare("off")
        insp.assert_not_called()

    async def test_dangling_symlink_never_followed_for_creation(self):
        self.user = user(os.path.join(self.root, "marcel"))
        os.symlink(os.path.join(self.root, "target"), self.user.home)
        with mock.patch("fastrdp_broker.home.creation_refusal", return_value=None), \
                self.assertRaisesRegex(home.HomeError, "symbolic link to a missing target"):
            await self.prepare()
        self.run.assert_not_called()
        self.assertFalse(os.path.exists(os.path.join(self.root, "target")))

    async def test_hung_nfs_does_not_block(self):
        self.user = user("/nfs/home/marcel")

        def hang(*a):
            self.release.wait(10)
            return home.Inspection("ok", "/nfs/home/marcel", uid=ME.pw_uid)

        with mock.patch("fastrdp_broker.home.inspect", side_effect=hang), \
                self.assertLogs("fastrdp.home", "WARNING") as logs:
            t0 = time.monotonic()
            await self.prepare(timeout=0.2)
        self.assertLess(time.monotonic() - t0, 2)
        self.assertIn("home directory not checked", "\n".join(logs.output))

    async def test_root_cannot_look_is_not_refused(self):
        self.user = user("/nfs/home/marcel")
        with mock.patch("fastrdp_broker.home.inspect", return_value=home.Inspection("unknown", "/nfs/home/marcel")):
            await self.prepare()
        self.run.assert_not_called()

    async def test_owned_by_another_uid(self):
        d = os.path.join(self.root, "marcel")
        os.mkdir(d)
        self.user = user(d, uid=ME.pw_uid + 1)
        for rc, ok in ((0, True), (1, False)):
            with self.subTest(rc=rc), mock.patch(
                    "fastrdp_broker.sysutil.run_dropped", return_value=sysutil.Result(rc, "", "")) as rd:
                if ok:
                    await self.prepare()
                else:
                    with self.assertRaisesRegex(home.HomeError, f"belongs to uid {ME.pw_uid}, not {ME.pw_uid + 1}, "
                                                                "and marcel cannot write to it"):
                        await self.prepare()
                self.assertEqual(rd.call_args.args[1:], ("test", "-w", d, "-a", "-x", d))

    async def test_nobody_owner_hints_at_id_mapping(self):
        self.user = user("/nfs/home/marcel")
        with mock.patch("fastrdp_broker.home.inspect", return_value=home.Inspection("ok", "/nfs/home/marcel", uid=65534)), \
                mock.patch("fastrdp_broker.sysutil.run_dropped", return_value=sysutil.Result(1, "", "")), \
                self.assertRaisesRegex(home.HomeError, "uid 65534 \\(nobody: NFSv4 id mapping"):
            await self.prepare()

    async def test_writability_test_timeout_is_not_a_refusal(self):
        self.user = user("/nfs/home/marcel")
        with mock.patch("fastrdp_broker.home.inspect", return_value=home.Inspection("ok", "/nfs/home/marcel", uid=1)), \
                mock.patch("fastrdp_broker.sysutil.run_dropped", side_effect=sysutil.CommandError("timeout: test")), \
                self.assertLogs("fastrdp.home", "WARNING"):
            await self.prepare()


class BrokerHomeCheckTests(unittest.IsolatedAsyncioTestCase):
    """A login whose home is unusable is refused before the back-end starts: reason
    "backend" (RDP 0x400), a log line naming the cause."""

    async def asyncSetUp(self):
        from fastrdp_broker.server import Broker

        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = make_cfg(self.tmp.name)
        self.cfg.broker.home_check = "create"
        self.broker = Broker(self.cfg)
        self.ensure = mock.AsyncMock(return_value=Target("127.0.0.1", 3390, "marcel", "tok", "", "tls"))
        for b in self.broker.backends.values():
            b.ensure = self.ensure
        self.home = os.path.join(self.tmp.name, "autofs/srv/home/marcel")
        self.patches = [
            mock.patch("fastrdp_broker.identity.resolve", side_effect=lambda n, r, a: user(self.home)),
            mock.patch("fastrdp_broker.pamauth.account_ok"),
        ]
        for p in self.patches:
            p.start()
        self.task = asyncio.create_task(self.broker.serve())
        for _ in range(50):
            if os.path.exists(self.cfg.broker.token_socket):
                break
            await asyncio.sleep(0.02)

    async def asyncTearDown(self):
        self.task.cancel()
        for p in self.patches:
            p.stop()
        self.broker.home_pool.shutdown(wait=True)
        self.tmp.cleanup()

    def login(self, sid="s1"):
        return request(self.cfg.broker.socket, {
            "op": "login", "session_id": sid, "method": "nla", "user": "marcel",
            "principal": "marcel@EXAMPLE.COM", "desktop_hint": "fastrdp:gnome"})

    async def test_missing_automount_root_refused_before_the_backend(self):
        with self.assertLogs("fastrdp.broker", "ERROR") as logs:
            reply = await self.login()
        self.assertEqual(reply, {"ok": False, "error": "session could not be started", "reason": "backend"})
        self.ensure.assert_not_called()
        self.assertIn(f"backend error: home directory {self.home} of marcel does not exist "
                      f"(parent {self.tmp.name}/autofs missing: automount not set up?)", "\n".join(logs.output))

    async def test_existing_home_logs_in(self):
        os.makedirs(self.home)
        reply = await self.login()
        self.assertTrue(reply["ok"], reply)
        self.ensure.assert_awaited_once()

    async def test_home_check_config(self):
        from test_units import load_example

        self.assertEqual(config.parse(load_example()).broker.home_check, "create")
        for good in ("create", "check", "off"):
            raw = load_example()
            raw["broker"]["home_check"] = good
            self.assertEqual(config.parse(raw).broker.home_check, good)
        raw = load_example()
        raw["broker"]["home_check"] = "yes"
        with self.assertRaises(config.ConfigError):
            config.parse(raw)

    async def test_home_create_roots_config(self):
        from test_units import load_example

        self.assertEqual(config.parse(load_example()).broker.home_create_roots, ["/home"])
        for good in ([], ["/home"], ["/home", "/srv/home"], ["/export/home dir"]):
            raw = load_example()
            raw["broker"]["home_create_roots"] = good
            self.assertEqual(config.parse(raw).broker.home_create_roots, good)
        for bad in ("/home", ["home"], ["/"], ["/home/"], ["/home/../etc"], ["//home"], ["/home/./x"],
                    [1], ["/home\n"]):
            raw = load_example()
            raw["broker"]["home_create_roots"] = bad
            with self.subTest(bad=bad), self.assertRaises(config.ConfigError):
                config.parse(raw)

    async def test_home_outside_create_roots_is_not_created(self):
        # the home's parent exists, but is not one of the roots
        self.home = os.path.join(self.tmp.name, "marcel")
        with mock.patch("fastrdp_broker.sysutil.run") as run, self.assertLogs("fastrdp.broker", "ERROR") as logs:
            reply = await self.login()
        self.assertEqual(reply["reason"], "backend")
        run.assert_not_called()
        self.ensure.assert_not_called()
        self.assertIn(f"home directory {self.home} of marcel does not exist, and the broker does not "
                      f"create it: {self.tmp.name} is not below [broker] home_create_roots (/home)",
                      "\n".join(logs.output))


class CommandErrorTests(unittest.IsolatedAsyncioTestCase):
    """Back-end errors name the command and its meaningful error lines, not a raw dump."""

    GRDCTL_STDERR = (
        "Init file credentials failed: Error creating directory /autofs: Permission denied\n"
        "**\n"
        "grdctl:ERROR:../src/grdctl.c:140:process_options: assertion failed: (priv->credentials)\n"
        "Bail out! grdctl:ERROR:../src/grdctl.c:140:process_options: assertion failed: (priv->credentials)\n"
    )

    def test_summary(self):
        self.assertEqual(
            sysutil.summarize(self.GRDCTL_STDERR),
            "Init file credentials failed: Error creating directory /autofs: Permission denied; "
            "grdctl:ERROR:../src/grdctl.c:140:process_options: assertion failed: (priv->credentials)")
        self.assertEqual(sysutil.summarize("\n \n"), "no error output")
        self.assertLessEqual(len(sysutil.summarize("x" * 1000)), 400)

    def test_describe_names_the_command_run_as_the_user(self):
        argv = ("systemd-run", "--machine=marcel@.host", "--user", "--wait", "--pipe", "--quiet",
                "--collect", "--", "grdctl", "--headless", "rdp", "set-tls-cert", "/var/lib/x")
        self.assertEqual(sysutil.describe(argv), "grdctl --headless rdp set-tls-cert ... (systemd-run as the user)")
        self.assertEqual(sysutil.describe(("systemctl", "start", "x.service")), "systemctl start x.service")
        # a system unit (home creation) is not "as the user"
        self.assertEqual(sysutil.describe(("systemd-run", "--wait", "--pipe", "--quiet", "--collect", "--",
                                           "mkhomedir_helper", "marcel", "0077", "/etc/skel", "0700")),
                         "mkhomedir_helper marcel 0077 /etc/skel ... (systemd-run)")

    async def test_failed_command_message(self):
        script = "printf '%s' \"$1\" >&2; exit 1"
        with self.assertRaises(sysutil.CommandError) as cm:
            await sysutil.run("sh", "-c", script, "sh", self.GRDCTL_STDERR)
        msg = str(cm.exception)
        self.assertTrue(msg.startswith("sh -c "), msg)
        self.assertIn("failed (1): Init file credentials failed", msg)
        self.assertEqual(msg.count("assertion failed"), 1)


if __name__ == "__main__":
    unittest.main()

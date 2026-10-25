# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""tests/lab/totp.py (LAB ONLY TOTP tool): RFC 6238 Appendix B vectors, base32 and
otpauth parsing, the secret sources, and the fresh-step logic (--min-left, --state,
--no-wait, --seconds-left) with an injected clock. Standard library only, no network.
"""

import base64
import importlib.util
import io
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "totp.py"
spec = importlib.util.spec_from_file_location("fastrdp_lab_totp", SCRIPT)
totp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(totp)

SEED = {"SHA1": b"12345678901234567890",
        "SHA256": b"12345678901234567890123456789012",
        "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234"}
# RFC 6238 Appendix B: time, then the 8-digit codes for SHA1, SHA256, SHA512
VECTORS = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]
B32 = base64.b32encode(SEED["SHA1"]).decode()   # GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ


class Clock:
    def __init__(self, t):
        self.t = t
        self.slept = []

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.slept.append(s)
        self.t += s


class Stdin(io.StringIO):
    def __init__(self, text="", tty=False):
        super().__init__(text)
        self.tty = tty

    def isatty(self):
        return self.tty


def run(argv, secret=B32, t=59.0, environ=None, tty=False):
    out, err, clock = io.StringIO(), io.StringIO(), Clock(t)
    rc = totp.run(argv, out=out, err=err, stdin=Stdin(secret, tty), environ=environ or {},
                  clock=clock, sleep=clock.sleep)
    return rc, out.getvalue(), err.getvalue(), clock


class Rfc6238(unittest.TestCase):
    def test_appendix_b(self):
        for t, *codes in VECTORS:
            for alg, want in zip(("SHA1", "SHA256", "SHA512"), codes):
                with self.subTest(t=t, alg=alg):
                    self.assertEqual(totp.totp(SEED[alg], t, 30, 8, alg), want)

    def test_cli_appendix_b(self):
        for t, *codes in VECTORS:
            for alg, want in zip(("SHA1", "SHA256", "SHA512"), codes):
                b32 = base64.b32encode(SEED[alg]).decode()
                rc, out, err, _ = run(["--algorithm", alg, "--digits", "8"], b32, t)
                self.assertEqual((rc, out, err), (0, want + "\n", ""))

    def test_rfc4226_hotp(self):   # RFC 4226 Appendix D, counters 0..9
        want = ["755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"]
        self.assertEqual([totp.hotp(SEED["SHA1"], c) for c in range(10)], want)

    def test_algorithm_names(self):
        for name in ("SHA1", "sha1", "HmacSHA1", "SHA-1"):
            self.assertEqual(totp.algorithm(name), "SHA1")
        self.assertEqual(totp.algorithm("HmacSHA512"), "SHA512")
        self.assertRaises(totp.SecretError, totp.algorithm, "MD5")


class Parsing(unittest.TestCase):
    def test_base32_forms(self):
        spaced = " ".join(B32.lower()[i:i + 4] for i in range(0, len(B32), 4))
        for text in (B32, B32.lower(), spaced, B32 + "\n", B32.rstrip("=")):
            self.assertEqual(totp.parse_secret(text), (SEED["SHA1"], {}))
        # padding present / absent (10 bytes -> 16 chars, 11 bytes -> padded)
        k = b"12345678901"
        padded = base64.b32encode(k).decode()
        self.assertTrue(padded.endswith("="))
        self.assertEqual(totp.parse_secret(padded)[0], k)
        self.assertEqual(totp.parse_secret(padded.rstrip("="))[0], k)

    def test_bad_base32(self):
        for text in ("", "   ", "not base32!", "0189"):
            with self.subTest(text=text):
                self.assertRaises(totp.SecretError, totp.parse_secret, text)

    def test_raw(self):
        self.assertEqual(totp.parse_secret("fastrdp-totp-test-secret\n", raw=True),
                         (b"fastrdp-totp-test-secret", {}))

    def test_otpauth(self):
        uri = ("otpauth://totp/fastrdp-test:alice?secret=" + B32.lower().rstrip("=")
               + "&digits=8&algorithm=SHA256&issuer=fastrdp-test&period=60")
        self.assertEqual(totp.parse_secret(uri),
                         (SEED["SHA1"], {"algorithm": "SHA256", "digits": 8, "period": 60}))
        self.assertEqual(totp.parse_secret("otpauth://totp/x?secret=" + B32),
                         (SEED["SHA1"], {}))
        for bad in ("otpauth://hotp/x?secret=" + B32 + "&counter=1",
                    "otpauth://totp/x?issuer=y",
                    "otpauth://totp/x?secret=" + B32 + "&digits=six",
                    "otpauth://totp/x?secret=" + B32 + "&algorithm=MD5"):
            with self.subTest(bad=bad):
                self.assertRaises(totp.SecretError, totp.parse_secret, bad)

    def test_otpauth_params_and_overrides(self):
        uri = ("otpauth://totp/x?secret=" + base64.b32encode(SEED["SHA512"]).decode()
               + "&algorithm=SHA512&digits=8")
        self.assertEqual(run([], uri, 59)[1], "90693936\n")
        # explicit options win over the URI
        self.assertEqual(run(["--digits", "6"], uri, 59)[1], "693936\n")

    def test_keycloak_fixture_unchanged(self):
        # kc_fixture.py imports totp() from here; its raw-key secret, as before
        sys.path.insert(0, str(HERE.parent / "keycloak"))
        try:
            import kc_fixture
        finally:
            sys.path.pop(0)
        key = kc_fixture.TOTP_SECRET
        self.assertEqual(kc_fixture.totp(at=1234567890), totp.totp(key.encode(), 1234567890))
        self.assertEqual(run(["--raw"], key, 1234567890)[1],
                         kc_fixture.totp(at=1234567890) + "\n")
        b32 = base64.b32encode(key.encode()).decode()
        self.assertEqual(run([], b32, 1234567890)[1], kc_fixture.totp(at=1234567890) + "\n")


class Sources(unittest.TestCase):
    def test_file_env_stdin(self):
        want = totp.totp(SEED["SHA1"], 59)
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "secret"
            f.write_text("\n" + B32 + "\n")
            self.assertEqual(run(["--secret-file", str(f)], "")[1], want + "\n")
            rc, out, err, _ = run(["--secret-file", str(Path(d) / "missing")], "")
            self.assertEqual((rc, out), (2, ""))
        self.assertEqual(run(["--secret-env", "LAB_SECRET"], "", environ={"LAB_SECRET": B32})[1],
                         want + "\n")
        self.assertEqual(run(["--secret-file", "-"])[1], want + "\n")
        self.assertEqual(run([])[1], want + "\n")

    def test_errors_do_not_leak(self):
        cases = [(["--secret-env", "NOPE"], B32, False),
                 ([], B32, True),                       # stdin is a terminal
                 (["--secret-file", "-", "--secret-env", "X"], B32, False),
                 ([], "OTPAUTH://hotp/x?secret=" + B32, False),
                 ([], B32 + "!!", False),
                 (["--digits", "4"], B32, False),
                 (["--algorithm", "MD5"], B32, False),
                 (["--min-left", "30"], B32, False)]
        for argv, secret, tty in cases:
            with self.subTest(argv=argv):
                rc, out, err, _ = run(argv, secret, tty=tty)
                self.assertEqual((rc, out), (2, ""))
                self.assertTrue(err.startswith("totp: "), err)
                self.assertNotIn(B32.rstrip("=")[:8], err.upper())

    def test_no_secret_option_on_argv(self):
        with self.assertRaises(SystemExit), \
             unittest.mock.patch("sys.stderr", io.StringIO()):
            totp.parser().parse_args(["--secret", B32])


class FreshStep(unittest.TestCase):
    def test_plan(self):
        p = totp.plan
        self.assertEqual(p(59, 30, 0, None), 1)
        self.assertEqual(p(59, 30, 5, None), 2)      # 1 s left < 5: next step
        self.assertEqual(p(55, 30, 5, None), 1)      # exactly 5 s left: fine
        self.assertEqual(p(31, 30, 5, 1), 2)         # step 1 used: next
        self.assertEqual(p(59, 30, 5, 1), 2)         # step 2 (future) has 30 s left
        self.assertEqual(p(61, 30, 0, 5), 6)         # used step far ahead (clock skew)

    def test_seconds_left(self):
        rc, out, _, clock = run(["--seconds-left"], t=50.4)
        self.assertEqual(out.splitlines(), [totp.totp(SEED["SHA1"], 50), "9"])
        self.assertEqual(clock.slept, [])

    def test_min_left_waits(self):
        rc, out, _, clock = run(["--min-left", "5", "--seconds-left"], t=58.0)
        self.assertEqual(clock.slept, [2.0])
        self.assertEqual(out.splitlines(), [totp.hotp(SEED["SHA1"], 2), "30"])

    def test_min_left_no_wait(self):
        rc, out, err, clock = run(["--min-left", "5", "--no-wait"], t=57.5)
        self.assertEqual((rc, out, clock.slept), (75, "", []))
        self.assertEqual(err, "totp: wait 3 s for a fresh step\n")

    def test_state_file(self):
        with tempfile.TemporaryDirectory() as d:
            st = str(Path(d) / "alice.step")
            rc, out1, _, c = run(["--state", st], t=31.0)
            self.assertEqual((rc, c.slept), (0, []))
            self.assertEqual(stat.S_IMODE(os.stat(st).st_mode), 0o600)
            self.assertEqual(Path(st).read_text(), "1\n")
            # same step again: refused with --no-wait, state unchanged
            rc, out, err, _ = run(["--state", st, "--no-wait"], t=40.0)
            self.assertEqual((rc, out, err), (75, "", "totp: wait 20 s for a fresh step\n"))
            self.assertEqual(Path(st).read_text(), "1\n")
            # ... and waits for the next step without it
            rc, out2, _, c = run(["--state", st, "--seconds-left"], t=40.0)
            self.assertEqual(c.slept, [20.0])
            self.assertEqual(out2.splitlines(), [totp.hotp(SEED["SHA1"], 2), "30"])
            self.assertNotEqual(out1.splitlines()[0], out2.splitlines()[0])
            self.assertEqual(Path(st).read_text(), "2\n")
            # a later step needs no wait
            self.assertEqual(run(["--state", st], t=95.0)[3].slept, [])
            self.assertEqual(Path(st).read_text(), "3\n")
            Path(st).write_text("garbage")
            self.assertEqual(run(["--state", st])[0], 2)


class Cli(unittest.TestCase):
    def test_subprocess(self):
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), "--seconds-left"],
                           input=B32, capture_output=True, text=True, timeout=10)
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        code, left = r.stdout.splitlines()
        self.assertRegex(code, r"^\d{6}$")
        self.assertTrue(0 < int(left) <= 30)


if __name__ == "__main__":
    unittest.main()

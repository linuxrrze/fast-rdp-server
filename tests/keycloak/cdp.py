# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Minimal Chrome DevTools Protocol client over --remote-debugging-pipe (stdlib only).

Chromium reads NUL-terminated JSON commands from fd 3 and writes replies/events to fd 4,
so no WebSocket library is needed. Enough for tests/keycloak/e2e.py: one page, the
WebAuthn domain (virtual authenticators), navigation and Runtime.evaluate.
"""

from __future__ import annotations

import json
import os
import select
import shutil
import subprocess
import tempfile
import time


class CdpError(Exception):
    pass


class Browser:
    def __init__(self, binary: str, extra_args: list[str] | None = None, log=None):
        self.profile = tempfile.mkdtemp(prefix="fastrdp-kc-chrome.")
        to_chrome_r, self._w = os.pipe()     # we write commands -> chrome fd 3
        self._r, from_chrome_w = os.pipe()   # chrome fd 4 -> we read
        args = [binary, "--headless", "--remote-debugging-pipe", "--no-first-run",
                "--no-default-browser-check", "--disable-gpu", "--no-sandbox",
                "--disable-dev-shm-usage", "--disable-background-networking",
                "--disable-features=PasswordManagerEnableSenderService,Translate",
                f"--user-data-dir={self.profile}", *(extra_args or []), "about:blank"]

        def child_fds():
            # Copy first: a pipe end may already be fd 3 or 4 (dup2 onto itself would keep
            # FD_CLOEXEC, and the second dup2 could overwrite the first end).
            r, w = os.dup(to_chrome_r), os.dup(from_chrome_w)
            os.dup2(r, 3)
            os.dup2(w, 4)
            os.set_inheritable(3, True)
            os.set_inheritable(4, True)

        # os.pipe() fds are not inheritable; only the dup2() copies 3 and 4 reach Chromium
        # (close_fds would close them again after preexec_fn).
        env = dict(os.environ)
        if env.get("CHROME_LIBS"):  # extracted shared libraries for a Chromium without system deps
            env["LD_LIBRARY_PATH"] = ":".join(filter(None, [env["CHROME_LIBS"], env.get("LD_LIBRARY_PATH")]))
        self.proc = subprocess.Popen(args, preexec_fn=child_fds, close_fds=False, env=env,  # noqa: S603
                                     stdout=subprocess.DEVNULL, stderr=log or subprocess.DEVNULL)
        os.close(to_chrome_r)
        os.close(from_chrome_w)
        self._buf = b""
        self._next = 0
        self.events: list[dict] = []
        self.dialogs: list[str] = []
        self.session = None
        target = self.call("Target.createTarget", {"url": "about:blank"})["targetId"]
        self.session = self.call("Target.attachToTarget", {"targetId": target, "flatten": True})["sessionId"]
        for domain in ("Page", "Runtime"):
            self.call(f"{domain}.enable")

    # ------------------------------------------------------------ transport
    def _read_msg(self, deadline: float) -> dict:
        while b"\0" not in self._buf:
            left = deadline - time.time()
            if left <= 0 or not select.select([self._r], [], [], left)[0]:
                raise CdpError("timeout waiting for the browser")
            chunk = os.read(self._r, 1 << 16)
            if not chunk:
                raise CdpError("browser closed the pipe")
            self._buf += chunk
        raw, self._buf = self._buf.split(b"\0", 1)
        return json.loads(raw)

    def _send(self, method: str, params: dict | None, session: str | None) -> int:
        self._next += 1
        msg = {"id": self._next, "method": method, "params": params or {}}
        if session:
            msg["sessionId"] = session
        os.write(self._w, json.dumps(msg).encode() + b"\0")
        return self._next

    def call(self, method: str, params: dict | None = None, timeout: float = 30, browser: bool = False) -> dict:
        want = self._send(method, params, None if browser else self.session)
        deadline = time.time() + timeout
        while True:
            reply = self._read_msg(deadline)
            if reply.get("id") == want:
                if "error" in reply:
                    raise CdpError(f"{method}: {reply['error']}")
                return reply.get("result", {})
            if "method" in reply:   # events; replies to earlier, timed-out calls are dropped
                self.events.append(reply)
                if reply["method"] == "Page.javascriptDialogOpening":
                    # alert()/confirm() block Runtime.evaluate: note the text, dismiss it
                    self.dialogs.append(reply["params"].get("message", ""))
                    self._send("Page.handleJavaScriptDialog", {"accept": True}, reply.get("sessionId"))

    def close(self) -> None:
        try:
            self.call("Browser.close", browser=True, timeout=5)
        except (CdpError, OSError):
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        for fd in (self._r, self._w):
            try:
                os.close(fd)
            except OSError:
                pass
        shutil.rmtree(self.profile, ignore_errors=True)

    # ------------------------------------------------------------ page helpers
    def js(self, expr: str, timeout: float = 30):
        res = self.call("Runtime.evaluate", {"expression": expr, "returnByValue": True,
                                             "awaitPromise": True}, timeout=timeout)
        if "exceptionDetails" in res:
            raise CdpError(f"JS error in {expr[:80]!r}: {res['exceptionDetails'].get('text')}")
        return res.get("result", {}).get("value")

    def url(self) -> str:
        return self.js("location.href") or ""

    def goto(self, url: str) -> None:
        self.call("Page.navigate", {"url": url})
        self.settle()

    def settle(self, timeout: float = 20) -> None:
        """Wait until the document is complete and the URL stopped changing."""
        deadline = time.time() + timeout
        last, stable = None, 0
        while time.time() < deadline:
            time.sleep(0.25)
            try:
                state = self.js("document.readyState + ' ' + location.href", timeout=5)
            except CdpError:
                stable = 0
                continue
            if state == last and state.startswith("complete"):
                stable += 1
                if stable >= 3:
                    return
            else:
                last, stable = state, 0
        raise CdpError(f"page did not settle: {last}")

    def wait_for(self, expr: str, timeout: float = 20) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if self.js(f"!!({expr})", timeout=5):
                    return
            except CdpError:
                pass
            time.sleep(0.25)
        raise CdpError(f"timeout waiting for {expr} at {self.url()}")

    def text(self) -> str:
        return self.js("document.body ? document.body.innerText : ''") or ""

    def clear_cookies(self) -> None:
        self.call("Network.clearBrowserCookies")

    # ------------------------------------------------------------ WebAuthn
    def add_authenticator(self) -> str:
        self.call("WebAuthn.enable", {"enableUI": False})
        return self.call("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "ctap2Version": "ctap2_1", "transport": "usb",
            "hasResidentKey": True, "hasUserVerification": True, "isUserVerified": True,
            "automaticPresenceSimulation": True}})["authenticatorId"]

    def credentials(self, authenticator: str) -> list[dict]:
        return self.call("WebAuthn.getCredentials", {"authenticatorId": authenticator})["credentials"]

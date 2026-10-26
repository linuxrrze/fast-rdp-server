#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
#
# LAB ONLY (signs a lab user in at Keycloak with password and TOTP or a software passkey
# and decides that user's waiting RDP login; never point it at a real account).
# What a phone does with the waiting screen's QR code, <approve_url>?login=<id>
# ([mfa] mode web, push_or_web or code_or_web; broker/webgate/fastrdp_webgate/app.py):
#   GET  <prefix>/approve?login=<id>  303 to the IdP (prompt=login, max_age=0; cookie
#                                     fastrdp_web_login holds state, nonce, PKCE, the id)
#   Keycloak: the login form (username, password), then the OTP form (otp); each form
#        is posted to its own action URL (login-actions/authenticate?session_code=...).
#        With --passkey-file: the webauth form (username page with passkeys, or WebAuthn as
#        second factor) instead, signed by tests/lab/passkey.py; challenge and rpId come
#        from the page's script, the origin is Keycloak's own.
#   GET  <prefix>/callback?code&state 303 back to <prefix>/approve?login=<id>, cookie
#                                     fastrdp_web_approve (the sign-in, 300 s)
#   GET  <prefix>/approve?login=<id>  the login's page: forms with csrf, id, login, decision
#   POST <prefix>/approve             csrf, id, login=<id> (bound), decision=approve|deny
#
#   tests/lab/approve.py --url https://rdp.example.com/web/approve [--login ID]
#       --user labuser1 [--password-file F --totp-secret-file F [--totp-state F]]
#       [--passkey-file F [--passkey-enrol]] [--ca-file F | --pin SHA256 ...] [--deny]
# --url: the approval page, its prefix (…/web) or the host (…/web/approve), or the QR
# code's URL with ?login=<id>. Without a login id (no journal line names it): the page's
# list, which must hold exactly one login, then that login's own page as the QR code
# opens it. --totp-state: the file the orchestrator uses too, so no time step is used
# twice (otpPolicyCodeReusable false). --pin: SHA-256 of a server certificate (the
# webgate's, Keycloak's; repeat it), instead of CA checks.
# --passkey-file: sign in with that passkey wherever Keycloak offers it (no password or
# code needed when the username page has passkeys). --passkey-enrol: the file must not
# exist yet; after password and TOTP, Keycloak's passkey registration (required action
# webauthn-register-passwordless, set by an admin on the lab user) gets a new passkey,
# which is written to the file (0600) and removed again if Keycloak refuses it.
# Never printed or logged: the password, the code, the passkey and its signatures,
# challenges, cookies, OIDC codes and states (URLs in messages are cut to scheme, host
# and path). Output: "approved <id>" or "denied <id>".
# Exit: 0 decided as asked, 1 failed (sign-in refused, no single login waiting, the
# webgate refused), 2 set-up error (options, files, TLS pin).
"""LAB ONLY: approve or deny a waiting RDP login like a phone after the QR code (see header)."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import html.parser
import http.client
import http.cookiejar
import importlib.util
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

_spec = importlib.util.spec_from_file_location("fastrdp_lab_totp", Path(__file__).resolve().parent / "totp.py")
totp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(totp)
_spec = importlib.util.spec_from_file_location("fastrdp_lab_passkey", Path(__file__).resolve().parent / "passkey.py")
passkey = importlib.util.module_from_spec(_spec)
sys.modules["fastrdp_lab_passkey"] = passkey   # dataclasses look the module up
_spec.loader.exec_module(passkey)

MAX_STEPS = 12          # redirects and forms of one sign-in
LOGIN_ID = re.compile(r"[A-Za-z0-9_-]{16,64}")   # app.SAFE_LOGIN_ID
MESSAGE_CLASS = re.compile(r"error|alert|feedback", re.I)
WEBAUTHN_SIGN = {"clientDataJSON", "authenticatorData", "signature", "credentialId"}
WEBAUTHN_REGISTER = {"clientDataJSON", "attestationObject", "publicKeyCredentialId"}
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "wbr"}


class SetupError(Exception):
    pass


class Failed(Exception):
    pass


def safe_url(url: str) -> str:
    """scheme://host/path: queries carry OIDC codes, states and Keycloak session codes."""
    u = urllib.parse.urlsplit(url)
    return f"{u.scheme}://{u.netloc}{u.path}"


def fingerprint(text: str) -> str:
    fp = re.sub(r"[^0-9a-f]", "", text.lower().removeprefix("sha256 fingerprint="))
    if len(fp) != 64:
        raise SetupError("--pin: 64 hex digits (openssl x509 -noout -fingerprint -sha256)")
    return fp


def approve_urls(url: str) -> tuple[str, str | None]:
    """(<prefix>/approve, the login id of a QR code URL or None)."""
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("https", "http") or not u.hostname:
        raise SetupError(f"--url: an http(s) URL, not {safe_url(url)!r}")
    path = u.path.rstrip("/")
    if not path:
        path = "/web/approve"
    elif not path.endswith("/approve"):
        path += "/approve"
    login = dict(urllib.parse.parse_qsl(u.query)).get("login")
    return urllib.parse.urlunsplit((u.scheme, u.netloc, path, "", "")), login


# --- HTTP ---------------------------------------------------------------------------------

class PinError(OSError):
    pass


class _PinnedConnection(http.client.HTTPSConnection):
    pins: frozenset = frozenset()

    def connect(self):
        super().connect()
        if hashlib.sha256(self.sock.getpeercert(binary_form=True)).hexdigest() not in self.pins:
            self.close()
            raise PinError(f"the certificate of {self.host} matches no --pin")


class _PinnedHandler(urllib.request.HTTPSHandler):
    """TLS checked by the certificate's SHA-256 only (lab hosts with self-signed ones)."""

    def __init__(self, pins: frozenset):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE   # replaced by the fingerprint check
        super().__init__(context=ctx)
        self.pins = pins

    def https_open(self, req):
        pins = self.pins

        def conn(host, **kw):
            c = _PinnedConnection(host, **kw)
            c.pins = pins
            return c
        return self.do_open(conn, req, context=self._context)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


@dataclasses.dataclass
class Response:
    status: int
    url: str
    location: str | None
    body: str


class Browser:
    """Cookies, no automatic redirects (each one is checked), TLS by CA file or pins."""

    def __init__(self, ca_file: str | None = None, pins: tuple[str, ...] = (), timeout: float = 20):
        self.jar = http.cookiejar.CookieJar()
        handlers = [urllib.request.HTTPCookieProcessor(self.jar), _NoRedirect]
        if pins:
            handlers.append(_PinnedHandler(frozenset(fingerprint(p) for p in pins)))
        elif ca_file:
            if not os.path.isfile(ca_file):
                raise SetupError(f"--ca-file {ca_file}: not found")
            handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))
        self.opener = urllib.request.build_opener(*handlers)
        self.timeout = timeout

    def request(self, url: str, form: list[tuple[str, str]] | None = None) -> Response:
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        req = urllib.request.Request(url, data=data, headers={"User-Agent": "fastrdp-lab-approve"})
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                return Response(r.status, url, r.headers.get("Location"), r.read(1 << 20).decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            with e:
                return Response(e.code, url, e.headers.get("Location"), e.read(1 << 20).decode("utf-8", "replace"))
        except urllib.error.URLError as e:
            if isinstance(e.reason, PinError):
                raise SetupError(str(e.reason)) from None
            raise Failed(f"{safe_url(url)}: {type(e.reason).__name__}: {e.reason}") from None
        except (OSError, http.client.HTTPException) as e:
            raise Failed(f"{safe_url(url)}: {type(e).__name__}") from None


# --- HTML ---------------------------------------------------------------------------------

@dataclasses.dataclass
class Form:
    action: str
    method: str
    fields: list[dict]      # {"tag", "type", "name", "value", "checked"}

    def names(self) -> set[str]:
        return {f["name"] for f in self.fields if f["name"]}

    def visible(self) -> set[str]:
        """Names of the fields a user fills in (not Keycloak's hidden WebAuthn form fields)."""
        return {f["name"] for f in self.fields if f["name"] and f["tag"] == "input"
                and f["type"] not in ("hidden", "submit", "button", "checkbox", "radio")}

    def value(self, name: str) -> str | None:
        return next((f["value"] for f in self.fields if f["name"] == name), None)

    def data(self, values: dict[str, str]) -> list[tuple[str, str]]:
        """What a browser sends: hidden and filled inputs, checked boxes, the first named
        submit button (Keycloak's name="login"); `values` filled in."""
        out, button = [], False
        for f in self.fields:
            name, kind = f["name"], f["type"]
            if not name:
                continue
            if kind in ("submit", "button") or f["tag"] == "button":
                if kind != "button" and not button:
                    out.append((name, f["value"]))
                    button = True
            elif kind in ("checkbox", "radio"):
                if f["checked"]:
                    out.append((name, f["value"] or "on"))
            else:
                out.append((name, values.get(name, f["value"])))
        return out


class Page(html.parser.HTMLParser):
    """The forms and the messages of a Keycloak or webgate page."""

    def __init__(self, text: str):
        super().__init__(convert_charrefs=True)
        self.forms: list[Form] = []
        self.messages: list[str] = []   # text of error/alert/feedback elements, then <p>s
        self.paragraphs: list[str] = []
        self.title = ""
        self._form: Form | None = None
        self._capture: list[list] = []   # [tag, depth, parts, target]
        self._in_title = False
        self.feed(text)
        self.close()

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        for c in self._capture:
            if c[0] == tag:
                c[1] += 1
        if tag == "form":
            self._form = Form(a.get("action", ""), a.get("method", "get").lower(), [])
            self.forms.append(self._form)
        elif tag in ("input", "button") and self._form is not None:
            self._form.fields.append({"tag": tag, "type": a.get("type", "text" if tag == "input" else "submit").lower(),
                                      "name": a.get("name", ""), "value": a.get("value", ""),
                                      "checked": "checked" in a})
        elif tag == "title":
            self._in_title = True
        if MESSAGE_CLASS.search(a.get("class", "") + " " + a.get("id", "")) and tag not in VOID | {"form"}:
            self._capture.append([tag, 1, [], self.messages])
        elif tag == "p":
            self._capture.append([tag, 1, [], self.paragraphs])

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None
        elif tag == "title":
            self._in_title = False
        for c in list(self._capture):
            if c[0] == tag:
                c[1] -= 1
                if c[1] == 0:
                    self._capture.remove(c)
                    text = " ".join("".join(c[2]).split())
                    if text and text not in c[3]:
                        c[3].append(text)

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        for c in self._capture:
            c[2].append(data)

    def message(self) -> str:
        return "; ".join(self.messages or self.paragraphs[:2]) or " ".join(self.title.split()) or "no message"


# --- the flow -----------------------------------------------------------------------------

def code_source(secret_file: str, state_file: str | None = None, min_left: float = 8, raw: bool = False,
                algorithm: str | None = None, digits: int | None = None, period: int | None = None,
                clock: Callable[[], float] = time.time,
                sleep: Callable[[float], None] = time.sleep) -> Callable[[], str]:
    """A function that hands out the next code (tests/lab/totp.py's rules: a fresh step with
    min_left seconds left, never a step the state file has seen)."""
    try:
        with open(os.path.expanduser(secret_file), encoding="utf-8") as f:
            line = next((ln for ln in f.read().splitlines() if ln.strip()), "")
        key, params = totp.parse_secret(line, raw)
        alg = totp.algorithm(algorithm) if algorithm else params.get("algorithm", "SHA1")
    except OSError as e:
        raise SetupError(f"TOTP secret file: {e.strerror}") from None
    except totp.SecretError as e:
        raise SetupError(f"TOTP secret: {e}") from None
    digits = digits or params.get("digits", 6)
    period = period or params.get("period", 30)

    def code() -> str:
        state = None
        try:
            if state_file:
                try:
                    state = totp.StateFile(os.path.expanduser(state_file))
                except OSError as e:
                    raise SetupError(f"TOTP state file: {e.strerror}") from None
            c = totp.plan(clock(), period, min_left, state.read() if state else None)
            wait = c * period - clock()
            if wait > 0:
                sleep(wait)
            if state:
                state.write(c)
            return totp.hotp(key, c, digits, alg)
        except totp.SecretError as e:
            raise SetupError(f"TOTP state: {e}") from None
        finally:
            if state:
                state.close()
    return code


@dataclasses.dataclass
class Result:
    login: str
    decision: str           # "approved" | "denied"
    message: str


def script_value(page: str, name: str) -> str | None:
    """A string of Keycloak's inline WebAuthn script (challenge : "…", rpId : '…')."""
    m = re.search(r"\b%s\s*:\s*([\"'])([^\"'<>]*)\1" % re.escape(name), page)
    return m.group(2) if m else None


class Passkeys:
    """tests/lab/passkey.py for the webauth and register forms of one sign-in."""

    def __init__(self, path: str, enrol: bool = False):
        self.path, self.enrol = os.path.expanduser(path), enrol
        if enrol and os.path.lexists(self.path):
            raise SetupError(f"--passkey-enrol: {path} exists (a new passkey never replaces a file)")
        if not enrol:
            self.open().close()     # readable, 0600, a passkey

    def open(self, create=None):
        try:
            return passkey.KeyFile(self.path, create)
        except OSError as e:
            raise SetupError(f"passkey file: {e.strerror}") from None
        except passkey.PasskeyError as e:
            raise SetupError(f"passkey file: {e}") from None

    @staticmethod
    def context(resp: Response) -> tuple[str, str]:
        """(origin, rpId) of a Keycloak page; the rpId must be its host or a parent domain."""
        u = urllib.parse.urlsplit(resp.url)
        host = (u.hostname or "").lower()
        rp_id = script_value(resp.body, "rpId") or host
        if not (host == rp_id or host.endswith("." + rp_id)):
            raise Failed(f"the IdP page at {safe_url(resp.url)} names rpId {rp_id!r}, not its host")
        return f"{u.scheme}://{u.netloc}", rp_id

    def assertion(self, resp: Response) -> dict[str, str]:
        challenge = script_value(resp.body, "challenge")
        if not challenge:
            raise Failed(f"passkey sign-in at {safe_url(resp.url)} without a challenge")
        origin, rp_id = self.context(resp)
        with self.open() as kf:
            if kf.key.rp_id != rp_id:
                raise SetupError(f"the passkey is for {kf.key.rp_id!r}, the IdP asks for {rp_id!r}")
            return kf.next_count().assertion(challenge, origin)

    def register(self, resp: Response) -> dict[str, str]:
        challenge, userid = script_value(resp.body, "challenge"), script_value(resp.body, "userid")
        if not (challenge and userid):
            raise Failed(f"passkey registration at {safe_url(resp.url)} without challenge or user id")
        origin, rp_id = self.context(resp)
        try:
            handle = passkey.unb64u(userid)
        except ValueError:
            raise Failed("passkey registration: the user id is not base64url") from None
        key = passkey.Passkey.new(rp_id, handle, script_value(resp.body, "username") or "")
        self.open(key).close()      # stored before Keycloak knows it
        return key.register(challenge, origin)

    def discard(self) -> None:
        """Keycloak refused the new passkey: remove its file again."""
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.path)


class Approver:
    def __init__(self, url: str, user: str, password: str | None, code: Callable[[], str] | None,
                 browser: Browser | None = None, log: Callable[[str], None] = lambda s: None,
                 passkeys: Passkeys | None = None):
        self.base, self.qr_login = approve_urls(url)
        self.user, self.password, self.code, self.passkeys = user, password, code, passkeys
        self.http = browser or Browser()
        self.log = log
        u = urllib.parse.urlsplit(self.base)
        self.origin, self.prefix = (u.scheme, u.netloc), u.path[:-len("/approve")]

    def at_webgate(self, url: str) -> bool:
        u = urllib.parse.urlsplit(url)
        return (u.scheme, u.netloc) == self.origin and u.path.startswith(self.prefix + "/")

    def page_url(self, login: str | None) -> str:
        return self.base + (f"?login={login}" if login else "")

    def open(self, url: str) -> tuple[Response, Page]:
        """GET a webgate page, signing in at the IdP when it sends us there; the webgate's
        page once it answers without a redirect."""
        state = {"registered": False}
        try:
            return self._open(url, state)
        except (Failed, SetupError):
            if state["registered"]:     # Keycloak did not go on to the webgate with it
                self.passkeys.discard()
            raise

    def _open(self, url: str, state: dict) -> tuple[Response, Page]:
        resp = self.http.request(url)
        password_sent = otp_sent = passkey_sent = False
        for _ in range(MAX_STEPS):
            if resp.status in (301, 302, 303, 307, 308) and resp.location:
                nxt = urllib.parse.urljoin(resp.url, resp.location)
                if urllib.parse.urlsplit(nxt).scheme not in ("https", "http"):
                    raise Failed(f"redirect to {urllib.parse.urlsplit(nxt).scheme}: from {safe_url(resp.url)}")
                resp = self.http.request(nxt)
                continue
            page = Page(resp.body)
            if self.at_webgate(resp.url):
                return resp, page
            posts = [f for f in page.forms if f.method == "post"]
            register = [f for f in posts if WEBAUTHN_REGISTER <= f.names()]
            if register:
                if state["registered"]:
                    raise Failed(f"the IdP did not accept the new passkey: {page.message()}")
                if not (self.passkeys and self.passkeys.enrol):
                    raise Failed("the IdP asks to register a passkey (required action; --passkey-enrol)")
                values = self.passkeys.register(resp)
                state["registered"] = True
                self.log("IdP: passkey registration")
                resp = self.http.request(urllib.parse.urljoin(resp.url, register[0].action or resp.url),
                                         register[0].data(values))
                continue
            webauth = [f for f in posts if WEBAUTHN_SIGN <= f.names()]
            if webauth and self.passkeys and not self.passkeys.enrol:
                if passkey_sent:
                    raise Failed(f"the IdP did not accept the passkey: {page.message()}")
                values, passkey_sent = self.passkeys.assertion(resp), True
                self.log("IdP: passkey")
                resp = self.http.request(urllib.parse.urljoin(resp.url, webauth[0].action or resp.url),
                                         webauth[0].data(values))
                continue
            forms = [f for f in posts if f.visible() & {"username", "password", "otp"}]
            if not forms:
                raise Failed(f"IdP page without a login form at {safe_url(resp.url)} "
                             f"(HTTP {resp.status}): {page.message()}")
            form = forms[0]
            names = form.visible()
            if names & {"otp", "password"} and passkey_sent:
                raise Failed(f"the IdP did not accept the passkey: {page.message()}")
            if names & {"otp", "password"} and self.password is None:
                raise Failed("the IdP asks for a password or a TOTP code (no passkey offered there; "
                             "--password-file, --totp-secret-file)")
            if "otp" in names:
                if otp_sent:
                    raise Failed(f"the IdP did not accept the TOTP code: {page.message()}")
                values, otp_sent = {"otp": self.code()}, True
                self.log("IdP: OTP form")
            elif "password" in names:
                if password_sent:
                    raise Failed(f"the IdP did not accept user name and password: {page.message()}")
                values, password_sent = {"username": self.user, "password": self.password}, True
                self.log("IdP: login form")
            else:
                values = {"username": self.user}
                self.log("IdP: user name form")
            target = urllib.parse.urljoin(resp.url, form.action or resp.url)
            resp = self.http.request(target, form.data(values))
        raise Failed(f"sign-in did not finish in {MAX_STEPS} steps (at {safe_url(resp.url)})")

    def webgate_page(self, login: str | None) -> Page:
        resp, page = self.open(self.page_url(login))
        if resp.status != 200:
            raise Failed(f"approval page: HTTP {resp.status}: {page.message()}")
        return page

    @staticmethod
    def decisions(page: Page) -> list[Form]:
        return [f for f in page.forms if f.method == "post" and f.action.endswith("/approve")
                and f.value("decision") in ("approve", "deny") and f.value("id")]

    def run(self, login: str | None = None, approve: bool = True) -> Result:
        login = login or self.qr_login
        if login is not None and not LOGIN_ID.fullmatch(login):
            raise SetupError("login id: 16 to 64 characters A-Z a-z 0-9 _ -")
        page = self.webgate_page(login)
        if login is None:
            ids = list(dict.fromkeys(f.value("id") for f in self.decisions(page)))
            if len(ids) != 1:
                raise Failed(f"{len(ids)} RDP logins wait for {self.user}, need exactly one: {page.message()}")
            login = ids[0]
            self.log(f"the one waiting login: {login}")
            page = self.webgate_page(login)     # its own page, as the QR code opens it
        decision = "approve" if approve else "deny"
        forms = [f for f in self.decisions(page) if f.value("id") == login and f.value("decision") == decision
                 and f.value("login") == login]
        if not forms:
            raise Failed(f"no {decision} button for login {login}: {page.message()}")
        resp = self.http.request(urllib.parse.urljoin(self.base, forms[0].action), forms[0].data({}))
        done = Page(resp.body)
        want = "Login approved" if approve else "Login denied"
        if resp.status != 200 or want not in done.message():
            raise Failed(f"{decision} refused: HTTP {resp.status}: {done.message()}")
        return Result(login, "approved" if approve else "denied", done.message())


def read_password(path: str) -> str:
    try:
        with open(os.path.expanduser(path), encoding="utf-8") as f:
            pw = f.readline().rstrip("\r\n")
    except OSError as e:
        raise SetupError(f"password file: {e.strerror}") from None
    if not pw:
        raise SetupError("password file: empty first line")
    return pw


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="approve.py", allow_abbrev=False,
                                 description="LAB ONLY: approve or deny a waiting RDP login on the "
                                 "webgate's approval page (QR code flow). Secrets only from files.")
    ap.add_argument("--url", required=True, help="approval page, prefix, host or QR code URL")
    ap.add_argument("--login", help="the login's id (default: from --url, else the single one waiting)")
    ap.add_argument("--user", required=True, help="Keycloak user name")
    ap.add_argument("--password-file")
    ap.add_argument("--totp-secret-file")
    ap.add_argument("--totp-state", help="tests/lab/totp.py --state file (one code per step)")
    ap.add_argument("--raw", action="store_true", help="the secret is Keycloak's raw key text")
    ap.add_argument("--algorithm")
    ap.add_argument("--digits", type=int)
    ap.add_argument("--period", type=int)
    ap.add_argument("--min-left", type=float, default=8, metavar="S")
    tls = ap.add_mutually_exclusive_group()
    tls.add_argument("--ca-file")
    tls.add_argument("--pin", action="append", default=[], metavar="SHA256")
    ap.add_argument("--passkey-file", help="tests/lab/passkey.py key file (0600)")
    ap.add_argument("--passkey-enrol", action="store_true",
                    help="register a new passkey into --passkey-file (after password and TOTP)")
    ap.add_argument("--deny", action="store_true")
    ap.add_argument("--timeout", type=float, default=20)
    ap.add_argument("-v", "--verbose", action="store_true", help="steps on stderr (nothing secret)")
    args = ap.parse_args(argv)
    try:
        if bool(args.password_file) != bool(args.totp_secret_file):
            raise SetupError("--password-file and --totp-secret-file go together")
        if not (args.password_file or args.passkey_file):
            raise SetupError("--password-file and --totp-secret-file, or --passkey-file")
        if args.passkey_enrol and not (args.passkey_file and args.password_file):
            raise SetupError("--passkey-enrol: --passkey-file, --password-file and --totp-secret-file")
        code = password = None
        if args.password_file:
            code = code_source(args.totp_secret_file, args.totp_state, args.min_left, args.raw,
                               args.algorithm, args.digits, args.period)
            password = read_password(args.password_file)
        passkeys = Passkeys(args.passkey_file, args.passkey_enrol) if args.passkey_file else None
        log = (lambda s: print(f"approve: {s}", file=sys.stderr)) if args.verbose else (lambda s: None)
        approver = Approver(args.url, args.user, password, code,
                            Browser(args.ca_file, tuple(args.pin), args.timeout), log, passkeys)
        res = approver.run(args.login, approve=not args.deny)
    except SetupError as e:
        print(f"approve: {e}", file=sys.stderr)
        return 2
    except Failed as e:
        print(f"approve: {e}", file=sys.stderr)
        return 1
    except Exception as e:   # noqa: BLE001 - never a traceback (locals may hold secrets)
        print(f"approve: unexpected {type(e).__name__}", file=sys.stderr)
        return 1
    print(f"{res.decision} {res.login}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

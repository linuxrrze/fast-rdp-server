# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""HTTP front of fastrdp-webgate (behind a TLS reverse proxy).

  GET  <prefix>/           not logged in -> redirect to the IdP; logged in -> desktop chooser
                           (?login=fresh: the IdP must ask again, after a sign-in without MFA)
  GET  <prefix>/callback   OIDC redirect target
  POST <prefix>/connect    -> broker web token -> encrypted Guacamole connection -> Guacamole
  POST <prefix>/rdp-desktop  desktop for RDP logins (mstsc, Windows App; broker web_set_desktop)
  GET  <prefix>/rdp/<desktop>.rdp  .rdp file for mstsc that names the desktop (alternate shell)
  GET  <prefix>/logout     drop the session, IdP logout if supported
  GET  <prefix>/approve    [mfa] mode web / push_or_web: fresh MFA sign-in at the IdP, then
                           the user's RDP logins waiting for approval (broker mfa_pending);
                           ?login=<id> (the waiting screen's QR code): that login first,
                           approvable although others wait (login_page())
  POST <prefix>/approve    Approve or Deny one of them (broker mfa_decide)
  GET  <prefix>/notify     [notify] backends: opt-in page for approval notifications
                           (docs/notifications.md), signed in like the desktop chooser
                           (?login=fresh as for <prefix>/)
  POST <prefix>/notify     ntfy topic on/new/off, remove a subscription, test message
  POST <prefix>/notify/webpush  store this browser's push subscription (notify.js)
  GET  <prefix>/sw.js, <prefix>/manifest.webmanifest, <prefix>/static/<file>
                           service worker, web app manifest, script and icons
"""

from __future__ import annotations

import hashlib
import html
import json
import logging
import re
import secrets
import socket
import time
import urllib.parse
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import guacjson, notify, pwa, webpush
from .config import Config
from .cookies import Signer
from .notify import Notifier
from .notifystore import MAX_SUBSCRIPTIONS, StoreError, TooManyError, check_account
from .oidc import MfaError, OidcError, Provider, pkce_pair

log = logging.getLogger("fastrdp.webgate")

SESSION_COOKIE = "fastrdp_web"
PENDING_COOKIE = "fastrdp_web_login"
# Sign-in for the approval page only (user + the IdP's auth_time); no desktop access.
APPROVE_COOKIE = "fastrdp_web_approve"
APPROVE_TTL = 300
# all used with fullmatch (match() with ^...$ lets a trailing newline through)
SAFE_USER = re.compile(r"[A-Za-z0-9._-]{1,128}")
SAFE_DESKTOP = re.compile(r"[A-Za-z0-9_-]{1,64}")
SAFE_REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
# <prefix>/approve?login=<id>: a pending login's id as the broker makes them
# (fastrdp_broker mfa.WebApprovals.new_id(), 22 characters)
SAFE_LOGIN_ID = re.compile(r"[A-Za-z0-9_-]{16,64}")
RDP_FILE = re.compile(r"/rdp/([A-Za-z0-9_-]{1,64})\.rdp")
SAFE_SUB_ID = re.compile(r"[A-Za-z0-9_-]{1,32}")
SAFE_CODE = re.compile(r"[0-9]{2}")
METHOD_LABELS = {"nla": "RDP client, Kerberos (NLA)", "tls": "RDP client, password"}
# Notes on the opt-in page after a change (?m=...)
NOTES = {"ntfy": "ntfy is set up: subscribe to the topic below.", "removed": "Removed.",
         "test": "Test notification sent to your devices.",
         "test-wait": "A test notification was sent less than a minute ago. Please wait a minute."}
# A login id the approval page does not find among the user's pending logins (unknown,
# finished, malformed or another user's: told apart nowhere)
NOT_WAITING = "This login is no longer waiting for approval."
# Where a sign-in may return to (pending cookie "r"); anything else goes to the chooser.
BACK_PATHS = ("/", "/notify")
CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'"
# The opt-in page also runs its own script (no inline scripts), registers the service
# worker, POSTs the subscription and links the manifest and icons.
NOTIFY_CSP = ("default-src 'none'; script-src 'self'; connect-src 'self'; worker-src 'self'; "
              "manifest-src 'self'; img-src 'self'; style-src 'unsafe-inline'; form-action 'self'; "
              "base-uri 'none'; frame-ancestors 'none'")


class BrokerError(Exception):
    """`reason`: the broker's refusal reason (fastrdp_broker/protocol.py), or
    "unavailable" if the broker gave no valid answer. `outcome`: how an already
    finished web approval ended (reason approval_finished)."""

    def __init__(self, message: str, reason: str = "denied", outcome: str | None = None):
        super().__init__(message)
        self.reason = reason
        self.outcome = outcome


def broker_request(path: str, op: str, user: str, timeout: float = 15, **fields) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(path)
        s.sendall(json.dumps({"op": op, "user": user, **fields}).encode() + b"\n")
        line = s.makefile("rb").readline(65536)
    try:
        reply = json.loads(line)
    except ValueError:
        raise BrokerError("no answer from broker", "unavailable") from None
    if not isinstance(reply, dict):
        raise BrokerError("no answer from broker", "unavailable")
    if not reply.get("ok"):
        reason, outcome = reply.get("reason"), reply.get("outcome")
        raise BrokerError(reply.get("error", "refused"), reason if isinstance(reason, str) else "denied",
                          outcome if isinstance(outcome, str) else None)
    return reply


def broker_web_token(path: str, user: str, timeout: float = 15) -> dict:
    return broker_request(path, "web_token", user, timeout)


def broker_web_desktops(path: str, user: str, timeout: float = 15) -> dict:
    """Desktops the broker allows this user (no token is issued)."""
    return broker_request(path, "web_desktops", user, timeout)


def broker_web_set_desktop(path: str, user: str, desktop: str | None, timeout: float = 15) -> dict:
    """Store the desktop for the user's RDP logins in the broker (None: the default again)."""
    return broker_request(path, "web_set_desktop", user, timeout, desktop=desktop)


def broker_mfa_pending(path: str, user: str, timeout: float = 15) -> list[dict]:
    """The user's RDP logins waiting for web approval."""
    return broker_request(path, "mfa_pending", user, timeout).get("pending", [])


def broker_mfa_decide(path: str, user: str, request_id: str, approve: bool, auth_time: int,
                      timeout: float = 15, bound: bool = False) -> dict:
    """Approve or deny one of them; `auth_time`: the IdP sign-in of the user deciding;
    `bound`: the user opened the page with this login's id (<prefix>/approve?login=<id>)."""
    extra = {"bound": True} if bound else {}
    return broker_request(path, "mfa_decide", user, timeout, id=request_id, approve=approve,
                          auth_time=auth_time, **extra)


def approve_path(login: str | None) -> str:
    """/approve, or /approve?login=<id> for an id that SAFE_LOGIN_ID accepts."""
    return f"/approve?login={login}" if login and SAFE_LOGIN_ID.fullmatch(login) else "/approve"


class Webgate:
    def __init__(self, cfg: Config, provider: Provider, signer: Signer, guac_key: bytes,
                 cert_fingerprint: str | None = None, notifier: Notifier | None = None):
        self.cfg = cfg
        # [notify] backends set: approval notifications (notify.py), opt-in page /notify
        self.notifier = notifier
        self.provider = provider
        self.signer = signer
        self.guac_key = guac_key
        self.prefix = cfg.webgate.path_prefix
        self.redirect_uri = cfg.webgate.public_url.rstrip("/") + self.prefix + "/callback"
        self.secure = cfg.webgate.public_url.startswith("https://")
        self.cert_fingerprint = cert_fingerprint

    def offers(self, desktop: str) -> bool:
        """Desktop offered on the web path ([webgate] desktops; empty = all the broker allows)."""
        return not self.cfg.webgate.desktops or desktop in self.cfg.webgate.desktops

    def username_from_claims(self, claims: dict) -> str | None:
        user = str(claims.get(self.cfg.oidc.username_claim, ""))
        if "@" in user:
            local, domain = user.rsplit("@", 1)
            if domain.lower() not in self.cfg.oidc.strip_domains:
                return None
            user = local
        return user if SAFE_USER.fullmatch(user) else None

    # ---------------------------------------------------------------- helpers
    def cookie(self, name: str, value: str, max_age: int) -> str:
        c = cookies.SimpleCookie()
        c[name] = value
        c[name]["path"] = self.prefix
        c[name]["httponly"] = True
        c[name]["samesite"] = "Lax"
        c[name]["max-age"] = max_age
        if self.secure:
            c[name]["secure"] = True
        return c.output(header="").strip()

    def rdp_file(self, desktop: str) -> str:
        """.rdp file for mstsc / the Windows App: the proxy and the desktop, the settings of
        docs/client-guide.md. No user name (the webgate does not know the UPN mstsc should
        send, docs/client-guide.md) and nothing secret: the user logs in as usual. Sound
        and microphone as the server offers them ([webgate] rdp_audio, rdp_audio_input):
        mstsc's own defaults would play sound but never record."""
        w = self.cfg.webgate
        address = w.rdp_host if w.rdp_port == 3389 else f"{w.rdp_host}:{w.rdp_port}"
        lines = [
            f"full address:s:{address}",
            f"alternate shell:s:fastrdp:{desktop}",
            "enablecredsspsupport:i:1",
            "authentication level:i:2",
            "prompt for credentials:i:0",
            "use redirection server name:i:0",
            "networkautodetect:i:1",
            "bandwidthautodetect:i:1",
            "connection type:i:7",
            # 0 = play on this computer, 2 = do not play; capture 1 = record from this computer
            f"audiomode:i:{0 if w.rdp_audio else 2}",
            f"audiocapturemode:i:{1 if w.rdp_audio and w.rdp_audio_input else 0}",
        ]
        return "\r\n".join(lines) + "\r\n"

    def connection_payload(self, user: str, token: str, desktop: str | None) -> dict:
        g = self.cfg.guacamole
        params = {
            "resize-method": "display-update",  # MS-RDPEDISP monitor layout on resize
            **g.rdp_parameters,
            # Not overridable by rdp_parameters: the proxy accepts web tokens only as a
            # TLS login (PROTOCOL_SSL, credentials in the Client Info PDU); guacd has no
            # Kerberos for NLA.
            "hostname": g.connection_host,
            "port": str(g.connection_port),
            "username": user,
            "password": token,
            "security": "tls",
        }
        if self.cert_fingerprint:
            # Pin the proxy's certificate: a local user binding the port while the proxy
            # restarts must not receive web tokens.
            params.pop("ignore-cert", None)
            params["cert-fingerprints"] = self.cert_fingerprint
        else:
            params["ignore-cert"] = "true"
        if desktop:
            params["initial-program"] = f"fastrdp:{desktop}"
        return {
            "username": user,
            "expires": int((time.time() + g.data_ttl) * 1000),
            "connections": {f"Desktop ({desktop or 'default'})": {"protocol": "rdp", "parameters": params}},
        }


def make_handler(app: Webgate):
    class Handler(BaseHTTPRequestHandler):
        server_version = "fastrdp-webgate"
        sys_version = ""

        def log_message(self, fmt, *args):  # no query strings in logs (they can carry codes)
            log.info("%s %s", loggable(self.command), loggable(self.path.split("?", 1)[0]))

        # -------------------------------------------------------- plumbing
        def send(self, status: int, body: str | bytes = "", headers: list[tuple[str, str]] = (),
                 content_type: str = "text/html; charset=utf-8", csp: str = CSP, cache: str = "no-store"):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(status)
            self.send_header("Cache-Control", cache)
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", csp)
            for k, v in headers:
                self.send_header(k, v)
            if data:
                self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def redirect(self, location: str, extra: list[tuple[str, str]] = ()):
            self.send(303, "", [("Location", location), *extra])

        def cookie_value(self, name: str) -> str | None:
            c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            return c[name].value if name in c else None

        def session(self) -> tuple[dict | None, str | None]:
            raw = self.cookie_value(SESSION_COOKIE)
            return app.signer.loads("session", raw), raw

        def route(self) -> tuple[str, dict]:
            parsed = urllib.parse.urlsplit(self.path)
            path = parsed.path
            if path == app.prefix:
                path += "/"
            if not path.startswith(app.prefix + "/"):
                return "", {}
            return path[len(app.prefix):], dict(urllib.parse.parse_qsl(parsed.query))

        def error_page(self, status: int, message: str):
            self.send(status, page("Remote desktop", f"<p>{html.escape(message)}</p>"
                                   f'<p><a href="{app.prefix}/">Try again</a></p>'))

        def broker_refused(self, what: str, user: str, exc: Exception):
            log.warning("broker refused %s for %s: %s", what, user, exc)
            reason = exc.reason if isinstance(exc, BrokerError) else "unavailable"  # OSError
            if reason == "unavailable":
                return self.error_page(503, "Remote desktops are not available right now. "
                                            "Please try again later.")
            if reason == "not_allowed":
                return self.error_page(403, "You are not allowed to use remote desktops.")
            return self.error_page(403, "Remote desktop access was refused for your account.")

        # ----------------------------------------------------------- GET
        def do_GET(self):
            path, query = self.route()
            if path == "/":
                sess, raw = self.session()
                if not sess:
                    return self.start_login(fresh=query.get("login") == "fresh")
                return self.chooser(sess["user"], app.signer.csrf(raw))
            if path == "/callback":
                return self.callback(query)
            if path == "/approve":
                if self.approval_without_mfa():
                    return
                login = query.get("login")
                if login is not None and not SAFE_LOGIN_ID.fullmatch(login):
                    return self.approval_message(404, NOT_WAITING)   # like an unknown id
                appr, raw = self.approval_session()
                if not appr:
                    return self.start_login(approve=True, login=login)
                return self.approve_page(appr, app.signer.csrf(raw), login)
            if path == "/logout":  # logout is a POST with CSRF token (see chooser form)
                return self.redirect(app.prefix + "/")
            if path == "/healthz":
                return self.send(200, "ok")
            if app.notifier and (path in ("/notify", "/sw.js", "/manifest.webmanifest")
                                 or path.startswith("/static/")):
                return self.notify_get(path, query)
            if m := RDP_FILE.fullmatch(path):
                sess, _ = self.session()
                if not sess:
                    return self.redirect(app.prefix + "/")
                return self.rdp_download(sess["user"], m.group(1))
            return self.error_page(404, "Not found.")

        def start_login(self, approve: bool = False, back: str = "/", fresh: bool = False,
                        login: str | None = None):
            """approve: sign-in for the approval page, always a fresh authentication at the
            IdP (an IdP session, e.g. of the desktop chooser, is not enough); login: the
            pending login it was opened for (?login=<id>, SAFE_LOGIN_ID). back: the
            page to return to after a chooser sign-in (BACK_PATHS). fresh: the IdP asks
            again although it has a session (after a sign-in without MFA, mfa_refused)."""
            state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
            verifier, challenge = pkce_pair()
            data = {"s": state, "n": nonce, "v": verifier}
            if approve:
                data.update(a=1, t=int(time.time()))
                if login:
                    data["l"] = login
            elif back != "/":
                data["r"] = back
            pending = app.signer.dumps("pending", data, 600)
            self.redirect(app.provider.authorize_url(app.redirect_uri, state, nonce, challenge,
                                                    fresh=approve or fresh),
                          [("Set-Cookie", app.cookie(PENDING_COOKIE, pending, 600))])

        def callback(self, query: dict):
            pending = app.signer.loads("pending", self.cookie_value(PENDING_COOKIE))
            if "error" in query:
                return self.error_page(403, f"Login failed: {query.get('error')}")
            if not pending or not secrets.compare_digest(query.get("state", ""), pending["s"]):
                return self.error_page(400, "Login state mismatch or expired.")
            if pending.get("a") and self.approval_without_mfa():
                return
            try:
                tokens = app.provider.exchange(query.get("code", ""), app.redirect_uri, pending["v"])
                claims = app.provider.id_token_claims(tokens, pending["n"])
                app.provider.check_mfa(claims)
                auth_time = app.provider.check_fresh(claims, pending["t"]) if pending.get("a") else None
            except MfaError as exc:
                return self.mfa_refused(exc, pending)
            except OidcError as exc:
                log.warning("OIDC login refused: %s", exc)
                return self.error_page(403, "Login was not accepted.")
            user = app.username_from_claims(claims)
            if user is None:
                log.warning("unusable username claim %r", claims.get(app.cfg.oidc.username_claim))
                return self.error_page(403, "Your account name cannot be used here.")
            if auth_time is not None:
                appr = app.signer.dumps("approve", {"user": user, "auth_time": auth_time}, APPROVE_TTL)
                log.info("web sign-in %s for login approval", user)
                return self.redirect(app.prefix + approve_path(pending.get("l")), [
                    ("Set-Cookie", app.cookie(APPROVE_COOKIE, appr, APPROVE_TTL)),
                    ("Set-Cookie", app.cookie(PENDING_COOKIE, "", 0)),
                ])
            sess = app.signer.dumps("session", {"user": user}, app.cfg.webgate.session_lifetime)
            log.info("web login %s", user)
            back = pending.get("r") if pending.get("r") in BACK_PATHS else "/"
            self.redirect(app.prefix + back, [
                ("Set-Cookie", app.cookie(SESSION_COOKIE, sess, app.cfg.webgate.session_lifetime)),
                ("Set-Cookie", app.cookie(PENDING_COOKIE, "", 0)),
            ])

        def mfa_refused(self, exc: MfaError, pending: dict):
            """A valid sign-in without proof of MFA: the user is told to sign in with the
            second factor (or to register one), the log says what Keycloak lacks. The page
            names only the IdP's host and its account console (Keycloak: <issuer>/account)."""
            o = app.cfg.oidc
            raw = exc.claims.get(o.username_claim)
            user = app.username_from_claims(exc.claims) or repr(raw)
            acr, amr = exc.claims.get("acr"), exc.claims.get("amr")
            if exc.claim == "acr":
                log.warning("OIDC login of %s refused: acr %r does not prove MFA (required: %s; amr: %r). "
                            "Keycloak issues acr %r only with a level-2 (MFA) step for this client: "
                            "fastrdp_web_passkeys: true, or a step-up browser flow "
                            "(docs/web-access.md#keycloak-setup)",
                            user, acr, ", ".join(o.required_acr), amr, o.required_acr[0])
            else:
                log.warning("OIDC login of %s refused: amr %r does not prove MFA (required: one of %s; "
                            "acr: %r). The IdP must list the second factor in amr "
                            "(fastrdp_web_required_amr_any, docs/web-access.md#keycloak-setup)",
                            user, amr, ", ".join(o.required_amr_any), acr)
            issuer = o.issuer.rstrip("/")
            host = urllib.parse.urlsplit(issuer).hostname or issuer
            account = html.escape(issuer + "/account")
            if pending.get("a"):
                again = approve_path(pending.get("l"))    # always a fresh sign-in
            else:
                again = (pending.get("r") if pending.get("r") in BACK_PATHS else "/") + "?login=fresh"
            body = (f"<p>Your sign-in at <b>{html.escape(host)}</b> did not use a second factor (MFA). "
                    "Sign in again with your passkey, security key or authenticator app.</p>"
                    "<p>If you are not asked for one, a second factor may not be set up for your "
                    f'account yet: add one in your account settings (<a href="{account}">{account}</a>) '
                    "or contact your administrator.</p>"
                    f'<p><a href="{app.prefix}{html.escape(again)}">Sign in again</a></p>')
            self.send(403, page("Second factor required", body))

        def chooser(self, user: str, csrf: str):
            # Only desktops the broker allows this user; the browser path also only those
            # the site offers on the web ([webgate] desktops).
            try:
                reply = broker_web_desktops(app.cfg.webgate.broker_socket, user)
            except (OSError, BrokerError) as exc:
                return self.broker_refused("desktop list", user, exc)
            allowed = [d for d in reply.get("desktops", []) if SAFE_DESKTOP.fullmatch(str(d.get("name", "")))]
            if not allowed:
                return self.error_page(403, "No remote desktop is available for your account.")
            default = reply.get("default", "")
            options = "".join(
                f'<option value="{html.escape(d["name"])}"{" selected" if d["name"] == default else ""}>'
                f'{html.escape(d.get("label") or d["name"])}</option>'
                for d in allowed if app.offers(d["name"])
            )
            body = f"<p>Signed in as <b>{html.escape(user)}</b>.</p>"
            if options:
                body += (
                    f'<form method="post" action="{app.prefix}/connect">'
                    f'<input type="hidden" name="csrf" value="{csrf}">'
                    f'<label>Desktop <select name="desktop">{options}'
                    f'</select></label> <button type="submit">Connect</button></form>'
                )
            body += self.rdp_section(allowed, reply.get("rdp_desktop"), default, csrf)
            if app.notifier:
                body += (f'<p><a href="{app.prefix}/notify">Notifications for RDP login approvals</a> '
                         "on your phone or in this browser</p>")
            body += (
                f'<form method="post" action="{app.prefix}/logout">'
                f'<input type="hidden" name="csrf" value="{csrf}">'
                f'<button type="submit">Sign out</button></form>'
            )
            self.send(200, page("Remote desktop", body))

        def rdp_section(self, allowed: list[dict], chosen: str | None, default: str, csrf: str) -> str:
            """Desktop for logins with an RDP app (mstsc, Windows App: no desktop choice of
            their own): store it in the broker, or download an .rdp file that names it."""
            labels = {d["name"]: d.get("label") or d["name"] for d in allowed}
            current = labels.get(default, default)
            how = "chosen here" if chosen else "the default"
            rows = []
            for d in allowed:
                name = html.escape(d["name"])
                if d["name"] == chosen:
                    use = "<b>used for Remote Desktop logins</b>"
                else:
                    use = (f'<form method="post" action="{app.prefix}/rdp-desktop" style="display:inline">'
                           f'<input type="hidden" name="csrf" value="{csrf}">'
                           f'<input type="hidden" name="desktop" value="{name}">'
                           f'<button type="submit">Use for Remote Desktop logins</button></form>')
                rows.append(f'<li style="margin:.6rem 0">{html.escape(labels[d["name"]])}<br>{use} '
                            f'<a href="{app.prefix}/rdp/{name}.rdp" download>Download .rdp file</a></li>')
            reset = ""
            if chosen:
                reset = (f'<form method="post" action="{app.prefix}/rdp-desktop">'
                         f'<input type="hidden" name="csrf" value="{csrf}">'
                         f'<input type="hidden" name="desktop" value="">'
                         f'<button type="submit">Use the default again</button></form>')
            return (
                "<h2>Remote Desktop app</h2>"
                "<p>Logins with Remote Desktop Connection (mstsc) or the Windows App currently get "
                f"<b>{html.escape(current)}</b> ({how}), unless the client names a desktop.</p>"
                f'<ul style="padding-left:1.2rem">{"".join(rows)}</ul>{reset}'
            )

        def rdp_download(self, user: str, desktop: str):
            try:
                reply = broker_web_desktops(app.cfg.webgate.broker_socket, user)
            except (OSError, BrokerError) as exc:
                return self.broker_refused("desktop list", user, exc)
            if desktop not in [d.get("name") for d in reply.get("desktops", [])]:
                log.warning("%s asked for an .rdp file for desktop %s, which is not allowed", user, desktop)
                return self.error_page(403, "This desktop is not available for your account.")
            log.info("%s downloaded an .rdp file for desktop %s", user, desktop)
            filename = f"{app.cfg.webgate.rdp_host}-{desktop}.rdp"
            self.send(200, app.rdp_file(desktop),
                      [("Content-Disposition", f'attachment; filename="{filename}"')],
                      content_type="application/x-rdp")

        def set_rdp_desktop(self, user: str, form: dict):
            desktop = form.get("desktop") or None
            if desktop is not None and not SAFE_DESKTOP.fullmatch(desktop):
                return self.error_page(400, "Unknown desktop.")
            try:
                broker_web_set_desktop(app.cfg.webgate.broker_socket, user, desktop)
            except BrokerError as exc:
                if exc.reason == "not_allowed" and desktop:
                    # also a user outside allow_groups: the chooser page says so next
                    log.warning("%s chose desktop %s for RDP logins, refused", user, desktop)
                    return self.error_page(403, "This desktop is not available for your account.")
                return self.broker_refused("desktop for RDP logins", user, exc)
            except OSError as exc:
                return self.broker_refused("desktop for RDP logins", user, exc)
            log.info("%s: desktop for RDP logins %s", user, desktop or "reset to the default")
            self.redirect(app.prefix + "/")

        # ------------------------------------------------------ approval
        def approval_session(self) -> tuple[dict | None, str | None]:
            raw = self.cookie_value(APPROVE_COOKIE)
            return app.signer.loads("approve", raw), raw

        def approval_without_mfa(self) -> bool:
            """True (after a page and a log line) if [oidc] does not make the IdP prove MFA:
            approving an RDP login is that login's second factor, so it always needs
            required_acr or required_amr_any; allow_without_mfa_proof is for the desktop
            chooser's sign-in only."""
            if app.cfg.oidc.proves_mfa():
                return False
            log.error("login approval refused: [oidc] required_acr and required_amr_any are empty, so "
                      "sign-ins do not prove MFA; approving RDP logins needs them (allow_without_mfa_proof "
                      "applies to the desktop chooser only, docs/web-access.md#approving-rdp-logins)")
            self.send(503, page("Approve RDP login", "<p>Approving RDP logins is not set up correctly on "
                                "this server. Please contact your administrator.</p>"))
            return True

        def approval_message(self, status: int, message: str, cookies: list[tuple[str, str]] = (),
                             login: str | None = None):
            back = html.escape(app.prefix + approve_path(login))
            self.send(status, page("Approve RDP login", f"<p>{html.escape(message)}</p>"
                                   f'<p><a href="{back}">Back to the approval page</a></p>'),
                      cookies)

        def login_item(self, p: dict, csrf: str, approve: bool, bound: bool = False) -> str:
            """One pending login: address, start, method, code, and its buttons (Approve only
            if `approve`; `bound`: the forms say the user came with this login's id)."""
            rid = str(p["id"])
            now = time.time()
            age = max(0, int(p.get("age_s") or 0))
            started = time.strftime("%H:%M:%S UTC", time.gmtime(now - age))
            form = (f'<form method="post" action="{app.prefix}/approve" style="display:inline">'
                    f'<input type="hidden" name="csrf" value="{csrf}">'
                    f'<input type="hidden" name="id" value="{rid}">'
                    + (f'<input type="hidden" name="login" value="{rid}">' if bound else ""))
            buttons = (f'{form}<input type="hidden" name="decision" value="approve">'
                       f'<button type="submit">Approve</button></form> ' if approve else "")
            buttons += (f'{form}<input type="hidden" name="decision" value="deny">'
                        f'<button type="submit">Deny</button></form>')
            address = html.escape(str(p.get("client_address") or "unknown address"))
            method = html.escape(METHOD_LABELS.get(p.get("method"), "RDP client"))
            code = str(p.get("code") or "")
            code = f", code <b>{code}</b>" if SAFE_CODE.fullmatch(code) else ""
            return (f"From <b>{address}</b> at <b>{started}</b> ({age} s ago)<br>"
                    f"{method}{code}<br>{buttons}")

        def approve_page(self, appr: dict, csrf: str, login: str | None = None):
            """The signed-in user's pending logins; with `login` (?login=<id>) that one
            first (login_page())."""
            user = appr["user"]
            try:
                pending = broker_mfa_pending(app.cfg.webgate.broker_socket, user)
            except (OSError, BrokerError) as exc:
                return self.broker_refused("pending logins", user, exc)
            pending = [p for p in pending if SAFE_REQUEST_ID.fullmatch(str(p.get("id", "")))]
            signed_in = f"<p>Signed in as <b>{html.escape(user)}</b>.</p>"
            if login:
                bound = [p for p in pending if p["id"] == login]
                if bound:
                    return self.login_page(user, bound[0], [p for p in pending if p["id"] != login], csrf)
                # not (or no longer) pending, or not the user's: told apart nowhere
                log.info("%s opened the approval page for a login that is not waiting", user)
                signed_in += f"<p><b>{html.escape(NOT_WAITING)}</b></p>"
            if not pending:
                body = (f"{signed_in}<p>No RDP login is waiting for your approval.</p>"
                        f'<p>Start the login in your RDP client, then <a href="{app.prefix}/approve">reload '
                        "this page</a>.</p>")
                return self.send(200, page("Approve RDP login", body))
            rows = [f'<li style="margin:1rem 0">'
                    f'{self.login_item(p, csrf, not p.get("single_pending_conflict"))}</li>' for p in pending]
            warning = ""
            if any(p.get("single_pending_conflict") for p in pending):
                warning = ("<p><b>More than one RDP login is waiting for your approval.</b> None of them "
                           "can be approved: somebody else may be using your password. Deny them, "
                           "start one new login and approve that one only.</p>")
            body = (f"{signed_in}"
                    "<p>Approve only a login you started yourself just now, from the address "
                    "shown (and the code, if your RDP client shows one). If you did not start it, "
                    "or somebody asked you to approve it, click <b>Deny</b>.</p>"
                    f"{warning}<ul style=\"padding-left:1.2rem\">{''.join(rows)}</ul>"
                    f'<p><a href="{app.prefix}/approve">Reload</a></p>')
            self.send(200, page("Approve RDP login", body))

        def login_page(self, user: str, p: dict, others: list[dict], csrf: str):
            """?login=<id> of a pending login of the user (the QR code on its waiting
            screen): that login with Approve (the broker allows it although others wait,
            "bound"), the user's other pending logins below with Deny only."""
            body = (f"<p>Signed in as <b>{html.escape(user)}</b>.</p>"
                    '<h2>This RDP login</h2>'
                    f"{self.others_warning(p, others)}"
                    f'<p style="border:2px solid;border-radius:.4rem;padding:.6rem 1rem">'
                    f"{self.login_item(p, csrf, True, bound=True)}</p>"
                    "<p>Approve it only if you started it yourself just now and its code is the one "
                    "your RDP window shows. If you did not start it, or somebody sent you this link "
                    "or asked you to approve it, click <b>Deny</b>.</p>")
            if others:
                rows = "".join(f'<li style="margin:1rem 0">{self.login_item(o, csrf, False)}</li>'
                               for o in others)
                body += ("<p><b>Another login with your password is waiting. Deny it if it is not "
                         f'yours.</b></p><ul style="padding-left:1.2rem">{rows}</ul>')
            body += f'<p><a href="{html.escape(app.prefix + approve_path(p["id"]))}">Reload</a></p>'
            self.send(200, page("Approve RDP login", body))

        def others_warning(self, p: dict, others: list[dict]) -> str:
            """Above the Approve button of a login-bound page while other logins of the user
            wait: the link may be an attacker's (sent to the user) for the attacker's own
            login, which the broker approves although others wait ("bound"). The code next
            to the warning, for comparing with the user's own RDP window."""
            if not others:
                return ""
            code = str(p.get("code") or "")
            compare = (f'Its code is <b style="font-size:1.4em">{code}</b>: approve it only if '
                       "<b>your own</b> RDP window shows this code." if SAFE_CODE.fullmatch(code) else
                       "Approve it only if you started it yourself just now, on your own screen.")
            return ('<div role="alert" style="border:3px solid #b3261e;background:#fdecea;color:#410e0b;'
                    'border-radius:.4rem;padding:.2rem 1rem;margin:1rem 0">'
                    f"<p><b>Warning: {len(others) + 1} logins with your account are waiting right now.</b> "
                    "Somebody else may be using your password.</p>"
                    f"<p>{compare} If you did not open this link from your own RDP window, or somebody "
                    "sent it to you, click <b>Deny</b>.</p></div>")

        def decide(self, form: dict):
            if self.approval_without_mfa():
                return
            appr, raw = self.approval_session()
            if not appr:
                return self.redirect(app.prefix + "/approve")
            if not secrets.compare_digest(form.get("csrf", ""), app.signer.csrf(raw)):
                return self.error_page(403, "Form expired, please try again.")
            rid, decision = form.get("id", ""), form.get("decision")
            if not SAFE_REQUEST_ID.fullmatch(rid) or decision not in ("approve", "deny"):
                return self.error_page(400, "Bad request.")
            user, approve = appr["user"], decision == "approve"
            # the user came with this login's id (?login=, login_page()): the broker approves
            # it although other logins of the user wait
            login = rid if form.get("login") == rid and SAFE_LOGIN_ID.fullmatch(rid) else None
            try:
                reply = broker_mfa_decide(app.cfg.webgate.broker_socket, user, rid, approve, appr["auth_time"],
                                          bound=login is not None)
            except BrokerError as exc:
                if exc.reason == "approval_stale":
                    # sign in again: the next GET starts a fresh login at the IdP
                    log.info("approval by %s refused: sign-in too old for that login", user)
                    return self.approval_message(
                        403, "Your sign-in is older than this login. Sign in again to approve it.",
                        [("Set-Cookie", app.cookie(APPROVE_COOKIE, "", 0))], login)
                if exc.reason == "approval_conflict":
                    return self.approval_message(
                        409, "More than one RDP login is waiting for your approval, so none of them can "
                             "be approved. Deny them and start one new login.")
                if exc.reason == "approval_finished":
                    outcome = {"approved": "was already approved", "denied": "was already denied",
                               "expired": "has timed out", "abandoned": "was cancelled by the RDP client"}
                    return self.approval_message(
                        409, f"This login {outcome.get(exc.outcome or '', 'is no longer waiting')}.")
                if exc.reason == "approval_unknown":
                    return self.approval_message(404, NOT_WAITING)
                return self.broker_refused("login approval", user, exc)
            except OSError as exc:
                return self.broker_refused("login approval", user, exc)
            log.info("web approval: %s %s an RDP login%s", user, "approved" if approve else "denied",
                     " (login-bound link)" if login else "")
            others = reply.get("others_pending")
            if approve and login and isinstance(others, int) and others > 0:
                log.warning("web approval: %s approved an RDP login via the login-bound link while %d other "
                            "login(s) of the account waited (somebody else with the password?)", user, others)
            if approve:
                return self.approval_message(200, "Login approved. Your RDP client continues now.")
            self.approval_message(200, "Login denied. If you did not start it, change your password.")

        # --------------------------------------------------- notifications
        def notify_get(self, path: str, query: dict):
            if path == "/sw.js":
                # scope <prefix>/ (the script's own directory); revalidated on every check
                return self.send(200, pwa.service_worker(), content_type="text/javascript; charset=utf-8",
                                 cache="no-cache")
            if path == "/manifest.webmanifest":
                return self.send(200, pwa.manifest(app.prefix), content_type="application/manifest+json",
                                 cache="no-cache")
            if path.startswith("/static/"):
                found = pwa.static_file(path[len("/static/"):])
                if found is None:
                    return self.error_page(404, "Not found.")
                return self.send(200, found[0], content_type=found[1], cache="no-cache", csp=NOTIFY_CSP)
            sess, raw = self.session()
            if not sess:
                return self.start_login(back="/notify", fresh=query.get("login") == "fresh")
            account = self.notify_account(sess["user"])
            if account is not None:
                self.notify_page(sess["user"], account, app.signer.csrf(raw), NOTES.get(query.get("m", ""), ""))

        def notify_account(self, user: str) -> str | None:
            """The local account the broker resolves the signed-in user to (it names that
            account in its events), if the user may use RDP; else an error page and None."""
            try:
                account = broker_web_desktops(app.cfg.webgate.broker_socket, user).get("user")
                return check_account(account)
            except (OSError, BrokerError) as exc:
                self.broker_refused("notification settings", user, exc)
            except StoreError as exc:
                log.warning("notifications for %s: %s", user, exc)
                self.error_page(403, "Notifications are not available for your account.")
            return None

        def notify_page(self, user: str, account: str, csrf: str, note: str = ""):
            n = app.cfg.notify
            try:
                subs = app.notifier.store.list(account)
            except (StoreError, OSError) as exc:
                log.error("subscriptions of %s not read: %s", account, exc)
                return self.error_page(503, "Notification settings are not available right now.")
            form = (f'<form method="post" action="{app.prefix}/notify" style="display:inline">'
                    f'<input type="hidden" name="csrf" value="{csrf}">')
            approve = app.cfg.webgate.public_url.rstrip("/") + app.prefix + "/approve"
            body = (f"<p>Signed in as <b>{html.escape(user)}</b>.</p>"
                    + (f"<p><b>{html.escape(note)}</b></p>" if note else "")
                    + "<p>When an RDP login with your account waits for your approval, you get a "
                    "notification that links to the approval page "
                    f"<b>{html.escape(approve)}</b>. Approving still needs a new sign-in there. "
                    "Approve only a login you started yourself (with the code, if your RDP client "
                    "shows one); a notification you did not expect means somebody has your password.</p>"
                    "<h2>Your devices</h2>")
            kinds = {"webpush": "browser", "ntfy": "ntfy app"}
            rows = []
            for sub in subs:
                if not SAFE_SUB_ID.fullmatch(str(sub["id"])):
                    continue
                created = time.strftime("%Y-%m-%d", time.gmtime(sub.get("created") or 0))
                off = "" if sub["type"] in n.backends else " (not used: switched off on this server)"
                rows.append(f'<li style="margin:.6rem 0">{html.escape(str(sub.get("label") or "unnamed"))} '
                            f'({kinds[sub["type"]]}, since {created}){off} '
                            f'{form}<input type="hidden" name="id" value="{sub["id"]}">'
                            '<button name="action" value="remove">Remove</button></form></li>')
            if rows:
                body += (f'<ul style="padding-left:1.2rem">{"".join(rows)}</ul>'
                         f'{form}<button name="action" value="test">Send a test notification</button></form>')
            else:
                body += "<p>None yet.</p>"
            if "webpush" in n.backends and app.notifier.vapid_key is not None:
                hashes = " ".join(hashlib.sha256(str(s.get("endpoint", "")).encode()).hexdigest()[:16]
                                  for s in subs if s["type"] == "webpush")
                body += (
                    "<h2>This browser</h2>"
                    f'<div id="webpush" data-key="{app.notifier.vapid_public_key}" data-csrf="{csrf}" '
                    f'data-post="{app.prefix}/notify/webpush" data-sw="{app.prefix}/sw.js" '
                    f'data-scope="{app.prefix}/" data-endpoints="{hashes}">'
                    '<p id="wp-status">Checking this browser…</p>'
                    '<p><label>Name of this device <input id="wp-label" maxlength="40" value="Browser"></label></p>'
                    '<p><button id="wp-on" type="button" hidden>Turn on notifications in this browser</button></p>'
                    "</div><noscript><p>Needs JavaScript.</p></noscript>"
                    "<p>iPhone and iPad (iOS 16.4 or later): open this page in Safari, tap Share, "
                    "then “Add to Home Screen”; open fastrdp from the home screen and turn "
                    "notifications on there.</p>")
            if "ntfy" in n.backends:
                body += self.ntfy_section([s for s in subs if s["type"] == "ntfy"], form)
            body += f'<p><a href="{app.prefix}/">Back to the desktops</a></p>'
            head = (f'<link rel="manifest" href="{app.prefix}/manifest.webmanifest">'
                    f'<link rel="apple-touch-icon" href="{app.prefix}/static/icon-192.png">'
                    f'<script src="{app.prefix}/static/notify.js" defer></script>')
            self.send(200, page("Login notifications", body, head), csp=NOTIFY_CSP)

        def ntfy_section(self, subs: list[dict], form: str) -> str:
            server = app.cfg.notify.ntfy_url
            out = "<h2>ntfy app</h2>"
            if not subs:
                return out + ("<p>Get the notifications in the ntfy app (Android, iOS) or ntfy's web app.</p>"
                              f'{form}<button name="action" value="ntfy-on">Set up ntfy</button></form>')
            topic = str(subs[0].get("topic", ""))
            url = f"{server}/{topic}"
            host = urllib.parse.urlsplit(server).netloc
            qr = pwa.qr_svg(url) or ""
            return out + (
                "<p>In the ntfy app: “Subscribe to topic”, topic "
                f"<code>{html.escape(topic)}</code>, “Use another server”: <code>{html.escape(server)}</code> "
                "(with the user name and password your administrator gave you for ntfy). Or scan or open:</p>"
                f'<p><a href="{html.escape(url)}">{html.escape(url)}</a> '
                f'(app link: <a href="ntfy://{html.escape(host)}/{html.escape(topic)}">ntfy://…</a>)</p>'
                f"<p>{qr}</p>"
                "<p>Keep the topic to yourself: whoever knows it and may read on that server sees "
                "your notifications. A new topic stops the old one.</p>"
                f'{form}<button name="action" value="ntfy-on">New topic</button></form> '
                f'{form}<input type="hidden" name="id" value="{subs[0]["id"]}">'
                '<button name="action" value="remove">Stop ntfy notifications</button></form>')

        def notify_post(self, user: str, form: dict):
            account = self.notify_account(user)
            if account is None:
                return
            action, store = form.get("action"), app.notifier.store
            try:
                if action == "ntfy-on" and "ntfy" in app.cfg.notify.backends:
                    # 128 random bits: the topic name is what keeps other readers out
                    store.add(account, {"type": "ntfy", "label": "ntfy",
                                        "topic": "fastrdp-" + secrets.token_urlsafe(16)})
                    log.info("%s: ntfy topic for approval notifications created", account)
                    note = "ntfy"
                elif action == "remove" and SAFE_SUB_ID.fullmatch(form.get("id", "")):
                    removed = store.remove(account, form["id"])
                    log.info("%s: notification subscription %s", account, "removed" if removed else "not found")
                    note = "removed"
                elif action == "test":
                    count = app.notifier.test(account)
                    if count is None:
                        log.info("%s: test notification not sent: one within %d s", account, notify.TEST_COOLDOWN)
                        note = "test-wait"
                    else:
                        log.info("%s: test notification to %d subscription(s)", account, count)
                        note = "test"
                else:
                    return self.error_page(400, "Bad request.")
            except TooManyError as exc:
                log.warning("notification settings of %s not stored: %s", account, exc)
                return self.error_page(409, "Not stored: remove a device first (at most "
                                            f"{MAX_SUBSCRIPTIONS}).")
            except (StoreError, OSError) as exc:
                log.error("notification settings of %s not stored: %s", account, exc)
                return self.error_page(503, "Notification settings are not available right now.")
            self.redirect(f"{app.prefix}/notify?m={note}")

        def webpush_post(self, user: str, form: dict):
            """notify.js: the browser's push subscription. Plain-text answers for the script."""
            plain = "text/plain; charset=utf-8"
            if "webpush" not in app.cfg.notify.backends or app.notifier.vapid_key is None:
                return self.send(404, "Web Push is not enabled here.", content_type=plain)
            endpoint, p256dh, auth = form.get("endpoint", ""), form.get("p256dh", ""), form.get("auth", "")
            label = re.sub(r"[^\w .,()@+-]", "", form.get("label", ""))[:40].strip() or "Browser"
            if not app.notifier.endpoint_allowed(endpoint):
                log.warning("%s: web push endpoint refused (not a known push service): %r", user, endpoint[:80])
                return self.send(400, "This browser's push service is not allowed here.", content_type=plain)
            try:
                webpush.check_subscription_keys(p256dh, auth)
            except webpush.WebPushError:
                return self.send(400, "Bad subscription.", content_type=plain)
            try:
                account = check_account(broker_web_desktops(app.cfg.webgate.broker_socket, user).get("user"))
                app.notifier.store.add(account, {"type": "webpush", "label": label, "endpoint": endpoint,
                                                 "p256dh": p256dh, "auth": auth})
            except (OSError, BrokerError, StoreError) as exc:
                log.warning("%s: web push subscription not stored: %s", user, exc)
                return self.send(403 if isinstance(exc, (BrokerError, StoreError)) else 503,
                                 "Not stored.", content_type=plain)
            log.info("%s: web push subscription %r stored (%s)", account, label,
                     urllib.parse.urlsplit(endpoint).hostname)
            self.send(200, "ok", content_type=plain)

        # ---------------------------------------------------------- POST
        def do_POST(self):
            path, _ = self.route()
            notify_paths = ("/notify", "/notify/webpush") if app.notifier else ()
            if path not in ("/connect", "/logout", "/approve", "/rdp-desktop", *notify_paths):
                return self.error_page(404, "Not found.")
            try:
                length = int(self.headers.get("Content-Length", "0") or 0)
            except ValueError:
                length = -1
            if not 0 <= length <= 4096:
                return self.error_page(400, "Bad request.")
            form = dict(urllib.parse.parse_qsl(self.rfile.read(length).decode(errors="replace")))
            if path == "/approve":
                return self.decide(form)
            sess, raw = self.session()
            if not sess:
                return self.redirect(app.prefix + "/")
            if not secrets.compare_digest(form.get("csrf", ""), app.signer.csrf(raw)):
                return self.error_page(403, "Form expired, please try again.")
            if path == "/rdp-desktop":
                return self.set_rdp_desktop(sess["user"], form)
            if path == "/notify":
                return self.notify_post(sess["user"], form)
            if path == "/notify/webpush":
                return self.webpush_post(sess["user"], form)
            if path == "/logout":
                target = app.provider.logout_url(app.cfg.webgate.public_url.rstrip("/") + app.prefix + "/")
                return self.redirect(target or app.prefix + "/",
                                     [("Set-Cookie", app.cookie(SESSION_COOKIE, "", 0))])
            desktop = form.get("desktop") or None
            if desktop and (not SAFE_DESKTOP.fullmatch(desktop) or not app.offers(desktop)):
                return self.error_page(400, "Unknown desktop.")
            try:
                reply = broker_web_token(app.cfg.webgate.broker_socket, sess["user"])
            except (OSError, BrokerError) as exc:
                return self.broker_refused("web token", sess["user"], exc)
            if desktop and desktop not in reply.get("desktops", []):
                # The broker would silently start the user's default desktop instead.
                log.warning("%s asked for desktop %s, which is not allowed", sess["user"], desktop)
                return self.error_page(403, "This desktop is not available for your account.")
            blob = guacjson.encrypt(app.guac_key, app.connection_payload(reply["user"], reply["token"], desktop))
            sep = "&" if "?" in app.cfg.guacamole.url else "?"
            self.redirect(app.cfg.guacamole.url + sep + "data=" + urllib.parse.quote(blob, safe=""))

    return Handler


def loggable(value: str) -> str:
    """A request value for a %s in the log: as it is if printable, else its repr (no
    line breaks or terminal escapes from a client in the journal)."""
    return value if value.isprintable() else repr(value)


def page(title: str, body: str, head: str = "") -> str:
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)}</title>{head}<style>"
        "body{font:16px system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;"
        "color:#1d1d1f;background:#fff}button,select{font:inherit;padding:.3rem .6rem}"
        "@media(prefers-color-scheme:dark){body{color:#eee;background:#1d1d1f}a{color:#8ab4ff}}"
        f"</style></head><body><h1>{html.escape(title)}</h1>{body}</body></html>"
    )


def serve(app: Webgate) -> None:
    host, port = app.cfg.webgate.listen.rsplit(":", 1)
    httpd = ThreadingHTTPServer((host.strip("[]"), int(port)), make_handler(app))
    if app.notifier:
        app.notifier.start()
    log.info("listening on %s", app.cfg.webgate.listen)
    httpd.serve_forever()

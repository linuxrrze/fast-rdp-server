# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""HTTP front of fastrdp-webgate (behind a TLS reverse proxy).

  GET  <prefix>/           not logged in -> redirect to the IdP; logged in -> desktop chooser
  GET  <prefix>/callback   OIDC redirect target
  POST <prefix>/connect    -> broker web token -> encrypted Guacamole connection -> Guacamole
  POST <prefix>/rdp-desktop  desktop for RDP logins (mstsc, Windows App; broker web_set_desktop)
  GET  <prefix>/rdp/<desktop>.rdp  .rdp file for mstsc that names the desktop (alternate shell)
  GET  <prefix>/logout     drop the session, IdP logout if supported
  GET  <prefix>/approve    [mfa] mode web / push_or_web: fresh MFA sign-in at the IdP, then
                           the user's RDP logins waiting for approval (broker mfa_pending)
  POST <prefix>/approve    Approve or Deny one of them (broker mfa_decide)
"""

from __future__ import annotations

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

from . import guacjson
from .config import Config
from .cookies import Signer
from .oidc import OidcError, Provider, pkce_pair

log = logging.getLogger("fastrdp.webgate")

SESSION_COOKIE = "fastrdp_web"
PENDING_COOKIE = "fastrdp_web_login"
# Sign-in for the approval page only (user + the IdP's auth_time); no desktop access.
APPROVE_COOKIE = "fastrdp_web_approve"
APPROVE_TTL = 300
SAFE_USER = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SAFE_DESKTOP = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
RDP_FILE = re.compile(r"/rdp/([A-Za-z0-9_-]{1,64})\.rdp")
METHOD_LABELS = {"nla": "RDP client, Kerberos (NLA)", "tls": "RDP client, password"}


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
                      timeout: float = 15) -> dict:
    """Approve or deny one of them; `auth_time`: the IdP sign-in of the user deciding."""
    return broker_request(path, "mfa_decide", user, timeout, id=request_id, approve=approve,
                          auth_time=auth_time)


class Webgate:
    def __init__(self, cfg: Config, provider: Provider, signer: Signer, guac_key: bytes,
                 cert_fingerprint: str | None = None):
        self.cfg = cfg
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
        send, docs/client-guide.md) and nothing secret: the user logs in as usual."""
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
            log.info("%s %s", self.command, self.path.split("?", 1)[0])

        # -------------------------------------------------------- plumbing
        def send(self, status: int, body: str = "", headers: list[tuple[str, str]] = (),
                 content_type: str = "text/html; charset=utf-8"):
            data = body.encode()
            self.send_response(status)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
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
                    return self.start_login()
                return self.chooser(sess["user"], app.signer.csrf(raw))
            if path == "/callback":
                return self.callback(query)
            if path == "/approve":
                appr, raw = self.approval_session()
                if not appr:
                    return self.start_login(approve=True)
                return self.approve_page(appr, app.signer.csrf(raw))
            if path == "/logout":  # logout is a POST with CSRF token (see chooser form)
                return self.redirect(app.prefix + "/")
            if path == "/healthz":
                return self.send(200, "ok")
            if m := RDP_FILE.fullmatch(path):
                sess, _ = self.session()
                if not sess:
                    return self.redirect(app.prefix + "/")
                return self.rdp_download(sess["user"], m.group(1))
            return self.error_page(404, "Not found.")

        def start_login(self, approve: bool = False):
            """approve: sign-in for the approval page, always a fresh authentication at the
            IdP (an IdP session, e.g. of the desktop chooser, is not enough)."""
            state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
            verifier, challenge = pkce_pair()
            data = {"s": state, "n": nonce, "v": verifier}
            if approve:
                data.update(a=1, t=int(time.time()))
            pending = app.signer.dumps("pending", data, 600)
            self.redirect(app.provider.authorize_url(app.redirect_uri, state, nonce, challenge, fresh=approve),
                          [("Set-Cookie", app.cookie(PENDING_COOKIE, pending, 600))])

        def callback(self, query: dict):
            pending = app.signer.loads("pending", self.cookie_value(PENDING_COOKIE))
            if "error" in query:
                return self.error_page(403, f"Login failed: {query.get('error')}")
            if not pending or not secrets.compare_digest(query.get("state", ""), pending["s"]):
                return self.error_page(400, "Login state mismatch or expired.")
            try:
                tokens = app.provider.exchange(query.get("code", ""), app.redirect_uri, pending["v"])
                claims = app.provider.id_token_claims(tokens, pending["n"])
                app.provider.check_mfa(claims)
                auth_time = app.provider.check_fresh(claims, pending["t"]) if pending.get("a") else None
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
                return self.redirect(app.prefix + "/approve", [
                    ("Set-Cookie", app.cookie(APPROVE_COOKIE, appr, APPROVE_TTL)),
                    ("Set-Cookie", app.cookie(PENDING_COOKIE, "", 0)),
                ])
            sess = app.signer.dumps("session", {"user": user}, app.cfg.webgate.session_lifetime)
            log.info("web login %s", user)
            self.redirect(app.prefix + "/", [
                ("Set-Cookie", app.cookie(SESSION_COOKIE, sess, app.cfg.webgate.session_lifetime)),
                ("Set-Cookie", app.cookie(PENDING_COOKIE, "", 0)),
            ])

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

        def approval_message(self, status: int, message: str, cookies: list[tuple[str, str]] = ()):
            self.send(status, page("Approve RDP login", f"<p>{html.escape(message)}</p>"
                                   f'<p><a href="{app.prefix}/approve">Back to the approval page</a></p>'),
                      cookies)

        def approve_page(self, appr: dict, csrf: str):
            user = appr["user"]
            try:
                pending = broker_mfa_pending(app.cfg.webgate.broker_socket, user)
            except (OSError, BrokerError) as exc:
                return self.broker_refused("pending logins", user, exc)
            now = time.time()
            rows = []
            for p in pending:
                rid = str(p.get("id", ""))
                if not SAFE_REQUEST_ID.match(rid):
                    continue
                age = max(0, int(p.get("age_s") or 0))
                started = time.strftime("%H:%M:%S UTC", time.gmtime(now - age))
                conflict = bool(p.get("single_pending_conflict"))
                form = (f'<form method="post" action="{app.prefix}/approve" style="display:inline">'
                        f'<input type="hidden" name="csrf" value="{csrf}">'
                        f'<input type="hidden" name="id" value="{rid}">')
                buttons = ("" if conflict else
                           f'{form}<input type="hidden" name="decision" value="approve">'
                           f'<button type="submit">Approve</button></form> ')
                buttons += (f'{form}<input type="hidden" name="decision" value="deny">'
                            f'<button type="submit">Deny</button></form>')
                address = html.escape(str(p.get("client_address") or "unknown address"))
                method = html.escape(METHOD_LABELS.get(p.get("method"), "RDP client"))
                rows.append(f'<li style="margin:1rem 0">From <b>{address}</b> at <b>{started}</b> '
                            f'({age} s ago)<br>{method}<br>{buttons}</li>')
            if not rows:
                body = (f"<p>Signed in as <b>{html.escape(user)}</b>.</p>"
                        "<p>No RDP login is waiting for your approval.</p>"
                        f'<p>Start the login in your RDP client, then <a href="{app.prefix}/approve">reload '
                        "this page</a>.</p>")
                return self.send(200, page("Approve RDP login", body))
            warning = ""
            if any(p.get("single_pending_conflict") for p in pending):
                warning = ("<p><b>More than one RDP login is waiting for your approval.</b> None of them "
                           "can be approved: somebody else may be using your password. Deny them, "
                           "start one new login and approve that one only.</p>")
            body = (f"<p>Signed in as <b>{html.escape(user)}</b>.</p>"
                    "<p>Approve only a login you started yourself just now, from the address "
                    "shown. If you did not start it, or somebody asked you to approve it, "
                    "click <b>Deny</b>.</p>"
                    f"{warning}<ul style=\"padding-left:1.2rem\">{''.join(rows)}</ul>"
                    f'<p><a href="{app.prefix}/approve">Reload</a></p>')
            self.send(200, page("Approve RDP login", body))

        def decide(self, form: dict):
            appr, raw = self.approval_session()
            if not appr:
                return self.redirect(app.prefix + "/approve")
            if not secrets.compare_digest(form.get("csrf", ""), app.signer.csrf(raw)):
                return self.error_page(403, "Form expired, please try again.")
            rid, decision = form.get("id", ""), form.get("decision")
            if not SAFE_REQUEST_ID.match(rid) or decision not in ("approve", "deny"):
                return self.error_page(400, "Bad request.")
            user, approve = appr["user"], decision == "approve"
            try:
                broker_mfa_decide(app.cfg.webgate.broker_socket, user, rid, approve, appr["auth_time"])
            except BrokerError as exc:
                if exc.reason == "approval_stale":
                    # sign in again: the next GET starts a fresh login at the IdP
                    log.info("approval by %s refused: sign-in too old for that login", user)
                    return self.approval_message(
                        403, "Your sign-in is older than this login. Sign in again to approve it.",
                        [("Set-Cookie", app.cookie(APPROVE_COOKIE, "", 0))])
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
                    return self.approval_message(404, "This login is no longer waiting for approval.")
                return self.broker_refused("login approval", user, exc)
            except OSError as exc:
                return self.broker_refused("login approval", user, exc)
            log.info("web approval: %s %s an RDP login", user, "approved" if approve else "denied")
            if approve:
                return self.approval_message(200, "Login approved. Your RDP client continues now.")
            self.approval_message(200, "Login denied. If you did not start it, change your password.")

        # ---------------------------------------------------------- POST
        def do_POST(self):
            path, _ = self.route()
            if path not in ("/connect", "/logout", "/approve", "/rdp-desktop"):
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
            if path == "/logout":
                target = app.provider.logout_url(app.cfg.webgate.public_url.rstrip("/") + app.prefix + "/")
                return self.redirect(target or app.prefix + "/",
                                     [("Set-Cookie", app.cookie(SESSION_COOKIE, "", 0))])
            desktop = form.get("desktop") or None
            if desktop and (not SAFE_DESKTOP.match(desktop) or not app.offers(desktop)):
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


def page(title: str, body: str) -> str:
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)}</title><style>"
        "body{font:16px system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;"
        "color:#1d1d1f;background:#fff}button,select{font:inherit;padding:.3rem .6rem}"
        "@media(prefers-color-scheme:dark){body{color:#eee;background:#1d1d1f}a{color:#8ab4ff}}"
        f"</style></head><body><h1>{html.escape(title)}</h1>{body}</body></html>"
    )


def serve(app: Webgate) -> None:
    host, port = app.cfg.webgate.listen.rsplit(":", 1)
    httpd = ThreadingHTTPServer((host.strip("[]"), int(port)), make_handler(app))
    log.info("listening on %s", app.cfg.webgate.listen)
    httpd.serve_forever()

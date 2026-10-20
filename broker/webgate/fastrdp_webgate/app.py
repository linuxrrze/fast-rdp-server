# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""HTTP front of fastrdp-webgate (behind a TLS reverse proxy).

  GET  <prefix>/           not logged in -> redirect to the IdP; logged in -> desktop chooser
  GET  <prefix>/callback   OIDC redirect target
  POST <prefix>/connect    -> broker web token -> encrypted Guacamole connection -> Guacamole
  GET  <prefix>/logout     drop the session, IdP logout if supported
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
SAFE_USER = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SAFE_DESKTOP = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class BrokerError(Exception):
    pass


def broker_request(path: str, op: str, user: str, timeout: float = 15) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(path)
        s.sendall(json.dumps({"op": op, "user": user}).encode() + b"\n")
        line = s.makefile("rb").readline(65536)
    try:
        reply = json.loads(line)
    except ValueError:
        raise BrokerError("no answer from broker") from None
    if not reply.get("ok"):
        raise BrokerError(reply.get("error", "refused"))
    return reply


def broker_web_token(path: str, user: str, timeout: float = 15) -> dict:
    return broker_request(path, "web_token", user, timeout)


def broker_web_desktops(path: str, user: str, timeout: float = 15) -> dict:
    """Desktops the broker allows this user (no token is issued)."""
    return broker_request(path, "web_desktops", user, timeout)


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
        def send(self, status: int, body: str = "", headers: list[tuple[str, str]] = ()):
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
                self.send_header("Content-Type", "text/html; charset=utf-8")
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
            if path == "/logout":  # logout is a POST with CSRF token (see chooser form)
                return self.redirect(app.prefix + "/")
            if path == "/healthz":
                return self.send(200, "ok")
            return self.error_page(404, "Not found.")

        def start_login(self):
            state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
            verifier, challenge = pkce_pair()
            pending = app.signer.dumps("pending", {"s": state, "n": nonce, "v": verifier}, 600)
            self.redirect(app.provider.authorize_url(app.redirect_uri, state, nonce, challenge),
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
            except OidcError as exc:
                log.warning("OIDC login refused: %s", exc)
                return self.error_page(403, "Login was not accepted.")
            user = app.username_from_claims(claims)
            if user is None:
                log.warning("unusable username claim %r", claims.get(app.cfg.oidc.username_claim))
                return self.error_page(403, "Your account name cannot be used here.")
            sess = app.signer.dumps("session", {"user": user}, app.cfg.webgate.session_lifetime)
            log.info("web login %s", user)
            self.redirect(app.prefix + "/", [
                ("Set-Cookie", app.cookie(SESSION_COOKIE, sess, app.cfg.webgate.session_lifetime)),
                ("Set-Cookie", app.cookie(PENDING_COOKIE, "", 0)),
            ])

        def chooser(self, user: str, csrf: str):
            # Only desktops the broker allows this user (and the site offers on the web).
            try:
                reply = broker_web_desktops(app.cfg.webgate.broker_socket, user)
            except (OSError, BrokerError) as exc:
                log.warning("broker refused desktop list for %s: %s", user, exc)
                return self.error_page(403, "You are not allowed to use remote desktops.")
            allowed = [d for d in reply.get("desktops", []) if app.offers(d.get("name", ""))]
            default = reply.get("default", "")
            options = "".join(
                f'<option value="{html.escape(d["name"])}"{" selected" if d["name"] == default else ""}>'
                f'{html.escape(d.get("label") or d["name"])}</option>'
                for d in allowed
            )
            if not options:
                return self.error_page(403, "No remote desktop is available for your account.")
            body = (
                f"<p>Signed in as <b>{html.escape(user)}</b>.</p>"
                f'<form method="post" action="{app.prefix}/connect">'
                f'<input type="hidden" name="csrf" value="{csrf}">'
                f'<label>Desktop <select name="desktop">{options}'
                f'</select></label> <button type="submit">Connect</button></form>'
                f'<form method="post" action="{app.prefix}/logout">'
                f'<input type="hidden" name="csrf" value="{csrf}">'
                f'<button type="submit">Sign out</button></form>'
            )
            self.send(200, page("Remote desktop", body))

        # ---------------------------------------------------------- POST
        def do_POST(self):
            path, _ = self.route()
            if path not in ("/connect", "/logout"):
                return self.error_page(404, "Not found.")
            try:
                length = int(self.headers.get("Content-Length", "0") or 0)
            except ValueError:
                length = -1
            if not 0 <= length <= 4096:
                return self.error_page(400, "Bad request.")
            form = dict(urllib.parse.parse_qsl(self.rfile.read(length).decode(errors="replace")))
            sess, raw = self.session()
            if not sess:
                return self.redirect(app.prefix + "/")
            if not secrets.compare_digest(form.get("csrf", ""), app.signer.csrf(raw)):
                return self.error_page(403, "Form expired, please try again.")
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
                log.warning("broker refused web token for %s: %s", sess["user"], exc)
                return self.error_page(403, "You are not allowed to use remote desktops.")
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

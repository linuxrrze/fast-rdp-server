# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Small privacyIDEA REST client (blocking; call via asyncio.to_thread)."""

from __future__ import annotations

import json
import logging
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from .config import PrivacyIdeaSection

log = logging.getLogger(__name__)


class PrivacyIdeaError(Exception):
    pass


class PrivacyIdea:
    def __init__(self, cfg: PrivacyIdeaSection):
        self.cfg = cfg
        self.base = cfg.url.rstrip("/")
        if not cfg.verify_tls:
            self.ssl = ssl._create_unverified_context()  # lab only, warned at startup
        else:
            self.ssl = ssl.create_default_context(cafile=cfg.ca_file or None)
        self._jwt: str | None = None
        self._jwt_time = 0.0

    def _request(self, method: str, path: str, params: dict, auth: str | None = None) -> dict:
        data = None
        url = self.base + path
        if method == "GET":
            url += "?" + urllib.parse.urlencode(params)
        else:
            data = urllib.parse.urlencode(params).encode()
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Accept", "application/json")
        if auth:
            req.add_header("Authorization", auth)
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.timeout, context=self.ssl) as resp:
                body = json.load(resp)
        except urllib.error.HTTPError as exc:
            try:
                body = json.load(exc)
            except ValueError:
                raise PrivacyIdeaError(f"{path}: HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise PrivacyIdeaError(f"{path}: {exc}") from None
        result = body.get("result", {})
        if not result.get("status", False):
            err = result.get("error", {}).get("message", "unknown error")
            raise PrivacyIdeaError(f"{path}: {err}")
        return body

    def _user_params(self, user: str) -> dict:
        params = {"user": user}
        if self.cfg.realm:
            params["realm"] = self.cfg.realm
        return params

    def check(self, user: str, passw: str, transaction_id: str | None = None) -> dict:
        params = self._user_params(user) | {"pass": passw}
        if transaction_id:
            params["transaction_id"] = transaction_id
        return self._request("POST", "/validate/check", params)

    def check_otp(self, user: str, otp: str) -> bool:
        return bool(self.check(user, otp)["result"].get("value"))

    def _service_auth(self) -> str:
        # privacyIDEA JWTs are valid for 1h by default; refresh well before.
        if self._jwt and time.monotonic() - self._jwt_time < 1800:
            return self._jwt
        with open(self.cfg.service_password_file, encoding="utf-8") as fh:
            password = fh.read().strip()
        body = self._request(
            "POST", "/auth", {"username": self.cfg.service_user, "password": password}
        )
        self._jwt = body["result"]["value"]["token"]
        self._jwt_time = time.monotonic()
        return self._jwt

    def trigger_challenge(self, user: str, password: str | None) -> str | None:
        """Start a challenge (e.g. push). Returns the transaction id or None."""
        if self.cfg.service_user:
            body = self._request(
                "POST", "/validate/triggerchallenge", self._user_params(user), self._service_auth()
            )
        elif password:
            # Requires privacyIDEA policy otppin=userstore: the user password triggers challenges.
            body = self.check(user, password)
        else:
            raise PrivacyIdeaError("cannot trigger challenge: no service account and no password")
        detail = body.get("detail", {})
        return detail.get("transaction_id")

    def wait_for_push(self, user: str, transaction_id: str) -> bool:
        deadline = time.monotonic() + self.cfg.push_timeout
        while time.monotonic() < deadline:
            body = self._request("GET", "/validate/polltransaction", {"transaction_id": transaction_id})
            if body["result"].get("value"):
                # Finalize: an empty pass together with the transaction id completes the push.
                final = self.check(user, "", transaction_id)
                return bool(final["result"].get("value"))
            time.sleep(self.cfg.poll_interval)
        return False

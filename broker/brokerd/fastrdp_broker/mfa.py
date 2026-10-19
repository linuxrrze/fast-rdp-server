"""Second factor via privacyIDEA (OTP appended to the password, or push)."""

from __future__ import annotations

import asyncio
import logging
import re

from .config import MfaSection
from .privacyidea import PrivacyIdea, PrivacyIdeaError

log = logging.getLogger(__name__)

YUBIKEY_OTP = re.compile(r"[cbdefghijklnrtuv]{44}$")


class MfaDenied(Exception):
    pass


def split_otp(secret: str, cfg: MfaSection) -> tuple[str, str] | None:
    """Split 'password+OTP' typed into one field. Returns (password, otp) or None.

    YubiKey OTPs (44 modhex chars) are recognised first, then numeric OTPs of the
    configured lengths in the configured order. Deployments should configure one
    TOTP length so a password ending in digits is not split ambiguously.
    """
    if cfg.yubikey_otp and len(secret) > 44 and YUBIKEY_OTP.search(secret):
        return secret[:-44], secret[-44:]
    for length in cfg.otp_lengths:
        if len(secret) > length and secret[-length:].isdigit():
            return secret[:-length], secret[-length:]
    return None


class SecondFactor:
    def __init__(self, cfg: MfaSection):
        self.cfg = cfg
        self.pi = PrivacyIdea(cfg.privacyidea) if cfg.mode != "none" else None

    @property
    def wants_otp_in_password(self) -> bool:
        return self.cfg.mode in ("otp", "otp_or_push")

    def exempt(self, groups: set[str]) -> bool:
        return self.cfg.mode == "none" or bool(groups & set(self.cfg.exempt_groups))

    async def verify(self, user: str, otp: str | None, password: str | None) -> str:
        """Run the configured second factor. Returns the factor used; raises MfaDenied."""
        assert self.pi is not None
        try:
            if otp is not None and self.wants_otp_in_password:
                if await asyncio.to_thread(self.pi.check_otp, user, otp):
                    return "otp"
                raise MfaDenied("OTP rejected")
            if self.cfg.mode in ("push", "otp_or_push"):
                txid = await asyncio.to_thread(self.pi.trigger_challenge, user, password)
                if not txid:
                    raise MfaDenied("no challenge-capable token for user")
                log.info("push challenge sent to %s (transaction %s)", user, txid)
                if await asyncio.to_thread(self.pi.wait_for_push, user, txid):
                    return "push"
                raise MfaDenied("push not confirmed in time")
            raise MfaDenied("OTP required: append it to the password")
        except PrivacyIdeaError as exc:
            log.error("privacyIDEA error for %s: %s", user, exc)
            raise MfaDenied("MFA service unavailable") from None

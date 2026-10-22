# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Progress messages for the proxy's waiting screen ([ui], proxy.ini [FastRDP]
WaitingScreen; protocol.py "progress").

While a login waits for the second factor or for the session start, the broker tells the
proxy module what the user should see: lines of text, a countdown and, with web approval,
a QR code of the approval page. Texts are templates in the configured language, or in the
language of the client's keyboard layout ([ui] language_from_keyboard), with these
placeholders: {user} (local account), {approve_url} ([ui] approve_url, short enough to
type on another device), {timeout}
(seconds), {method} (push, web, push_or_web), {desktop} (the desktop's label), {code}
(the web approval's two-digit correlation code, also on the approval page and in
notifications; "" for a push), {running} (the desktop of a running session) and {count}
(the desktop picker's rows). A line that names {approve_url} is left out while
approve_url is "", one that names {code} while there is no code.

The QR code names the pending login as well, <approve_url>?login=<id> (login_url(); the
id of mfa.WebApprovals): the approval page then shows that login first and may approve
it although other logins of the user wait ([mfa] web_approval_single_pending). The id
is no credential; the page still wants the user's fresh MFA sign-in.

The desktop picker ([broker] desktop_picker, Broker.pick_desktop) uses picker_title (the
lines above the rows; {desktop}: the preselected one), picker_hint (one line below them,
cut at the panel's width), picker_countdown, and for the rows picker_running (the
desktop of a running session) and picker_reconnects (another desktop of the same
back-end: choosing it reconnects to the running {running}). """

from __future__ import annotations

import string

from . import qrcode
from .config import UiSection

TEXT_KEYS = ("mfa_push", "mfa_web", "mfa_push_or_web", "qr_hint", "session_start", "countdown",
             "picker_title", "picker_hint", "picker_countdown", "picker_running", "picker_reconnects")
PLACEHOLDERS = ("user", "approve_url", "timeout", "method", "desktop", "code", "running", "count")
MAX_TEMPLATE = 2000
MAX_LINES = 12      # the module shows at most 16 after wrapping
MAX_LINE = 200      # characters per line
MAX_OPTION_LABEL = 44  # desktop picker rows: the module shows 48 glyphs with "[1] "
QR_MAX_VERSION = 10  # 57 x 57 modules; [ui] approve_url with the id fits (config.MAX_APPROVE_URL)

BUILTIN_TEXTS: dict[str, dict[str, str]] = {
    "en": {
        "mfa_push": "Approve the sign-in\n"
                    "Confirm the push notification for {user} on your phone.",
        "mfa_web": "Approve the sign-in\n"
                   "Sign in on the approval page and approve this login:\n"
                   "{approve_url}\n"
                   "Login code: {code}",
        "mfa_push_or_web": "Approve the sign-in\n"
                           "Confirm the push notification on your phone, or sign in on the "
                           "approval page and approve this login:\n"
                           "{approve_url}\n"
                           "Login code: {code}",
        "qr_hint": "Scan the code to open the approval page on your phone.",
        "session_start": "Connecting to your desktop ({desktop})…",
        "countdown": "Time left:",
        "picker_title": "Choose your desktop",
        "picker_hint": "1-{count}, arrow keys + Enter, or click. Esc: {desktop}",
        "picker_countdown": "Continuing in",
        "picker_running": "{desktop} (running)",
        "picker_reconnects": "{desktop} (opens the running {running})",
    },
    "de": {
        "mfa_push": "Anmeldung bestätigen\n"
                    "Bitte bestätigen Sie die Push-Benachrichtigung für {user} auf "
                    "Ihrem Telefon.",
        "mfa_web": "Anmeldung bestätigen\n"
                   "Melden Sie sich auf der Freigabeseite an und bestätigen Sie diese "
                   "Anmeldung:\n"
                   "{approve_url}\n"
                   "Anmeldecode: {code}",
        "mfa_push_or_web": "Anmeldung bestätigen\n"
                           "Bestätigen Sie die Push-Benachrichtigung auf Ihrem Telefon oder "
                           "melden Sie sich auf der Freigabeseite an und bestätigen Sie "
                           "diese Anmeldung:\n"
                           "{approve_url}\n"
                           "Anmeldecode: {code}",
        "qr_hint": "Code scannen, um die Freigabeseite auf dem Telefon zu öffnen.",
        "session_start": "Verbindung zu Ihrem Desktop ({desktop}) wird hergestellt…",
        "countdown": "Verbleibend:",
        "picker_title": "Desktop auswählen",
        "picker_hint": "1-{count}, Pfeiltasten + Eingabe oder Klick. Esc: {desktop}",
        "picker_countdown": "Weiter in",
        "picker_running": "{desktop} (läuft)",
        "picker_reconnects": "{desktop} (öffnet das laufende {running})",
    },
}

# Primary language of a Windows LANGID (low 10 bits; the keyboard layout's low word,
# [MS-RDPBCGR] 2.2.1.3.2 keyboardLayout) -> ISO 639-1
KEYBOARD_LANGUAGES = {
    0x01: "ar", 0x02: "bg", 0x03: "ca", 0x04: "zh", 0x05: "cs", 0x06: "da", 0x07: "de",
    0x08: "el", 0x09: "en", 0x0a: "es", 0x0b: "fi", 0x0c: "fr", 0x0d: "he", 0x0e: "hu",
    0x0f: "is", 0x10: "it", 0x11: "ja", 0x12: "ko", 0x13: "nl", 0x14: "nb", 0x15: "pl",
    0x16: "pt", 0x18: "ro", 0x19: "ru", 0x1a: "hr", 0x1b: "sk", 0x1c: "sq", 0x1d: "sv",
    0x1f: "tr", 0x22: "uk", 0x24: "sl", 0x25: "et", 0x26: "lv", 0x27: "lt",
}


def login_url(approve_url: str, request_id: str) -> str:
    """The approval page for one pending login: <approve_url>?login=<id> (&login= if the
    URL has a query already; before a #fragment)."""
    url, hash_, fragment = approve_url.partition("#")
    return f"{url}{'&' if '?' in url else '?'}login={request_id}{hash_}{fragment}"


def check_template(template: object) -> None:
    """Raises ValueError unless `template` is a text with known placeholders only (no
    attribute or index access, no format specifications)."""
    if not isinstance(template, str):
        raise ValueError("must be a string")
    if len(template) > MAX_TEMPLATE:
        raise ValueError(f"longer than {MAX_TEMPLATE} characters")
    if any(ord(c) < 32 and c != "\n" for c in template) or "\x7f" in template:
        raise ValueError("control characters (other than line breaks)")
    try:
        fields = list(string.Formatter().parse(template))
    except ValueError as exc:
        raise ValueError(f"{exc} (write {{{{ and }}}} for braces)") from None
    for _literal, name, spec, conversion in fields:
        if name is None:
            continue
        if name not in PLACEHOLDERS or spec or conversion:
            raise ValueError(f"unknown placeholder {{{name}}}; known: "
                             + ", ".join(f"{{{p}}}" for p in PLACEHOLDERS))


class WaitingTexts:
    def __init__(self, cfg: UiSection):
        self.cfg = cfg
        self.texts = {lang: dict(t) for lang, t in BUILTIN_TEXTS.items()}
        for lang, table in cfg.texts.items():
            self.texts.setdefault(lang, dict(BUILTIN_TEXTS["en"])).update(table)

    def language(self, keyboard_layout: int | None) -> str:
        """[ui] language, or the keyboard layout's language if it has texts."""
        if self.cfg.language_from_keyboard and keyboard_layout:
            lang = KEYBOARD_LANGUAGES.get(keyboard_layout & 0x3FF)
            if lang in self.texts:
                return lang
        return self.cfg.language

    def lines(self, lang: str, key: str, **values) -> list[str]:
        values = {**dict.fromkeys(PLACEHOLDERS, ""), "approve_url": self.cfg.approve_url, **values}
        out = []
        for line in self.texts[lang][key].split("\n"):
            if "{approve_url}" in line and not self.cfg.approve_url:
                continue
            if "{code}" in line and not values["code"]:
                continue
            out.append(line.format(**values)[:MAX_LINE])
        return out[:MAX_LINES]

    def mfa(self, lang: str, method: str, timeout: int, user: str, code: str | None = None,
            request_id: str | None = None) -> dict:
        """{"progress": "mfa", ...} for a push, web approval or both (method); `code`, `request_id`:
        the web approval's correlation code and id (in the QR code). The QR code is encoded
        per login (at most some 50 ms, once or twice per login)."""
        msg = {"progress": "mfa", "method": method, "timeout_s": int(timeout),
               "lines": self.lines(lang, f"mfa_{method}", user=user, timeout=int(timeout), method=method,
                                   code=code or ""),
               "countdown": self.texts[lang]["countdown"]}
        if method in ("web", "push_or_web") and self.cfg.approve_url:
            msg["approve_url"] = self.cfg.approve_url
            if self.cfg.qr_code:
                url = login_url(self.cfg.approve_url, request_id) if request_id else self.cfg.approve_url
                msg["qr"] = qrcode.encode(url.encode(), QR_MAX_VERSION)
                msg["lines"] = (msg["lines"] + self.lines(lang, "qr_hint", user=user))[:MAX_LINES]
        return msg

    def text(self, lang: str, key: str, **values) -> str:
        """One-line text (the first line of the template)."""
        lines = self.lines(lang, key, **values)
        return lines[0] if lines else ""

    def picker(self, lang: str, user: str, options: list[dict], default: str, timeout: int) -> dict:
        """{"progress": "choose_desktop", ...} (protocol.py). `options`: {"name", "label",
        "running": bool, "reconnects": label of the same back-end's running desktop or None};
        `default`: the preselected name."""
        rows = []
        for o in options:
            label = o["label"]
            if o.get("running"):
                label = self.text(lang, "picker_running", user=user, desktop=label, running=label)
            elif o.get("reconnects"):
                label = self.text(lang, "picker_reconnects", user=user, desktop=label, running=o["reconnects"])
            rows.append({"name": o["name"], "label": label[:MAX_OPTION_LABEL], "running": bool(o.get("running"))})
        default_label = next((o["label"] for o in options if o["name"] == default), default)
        values = {"user": user, "desktop": default_label, "timeout": int(timeout), "count": len(options)}
        return {"progress": "choose_desktop", "options": rows, "default": default,
                "timeout_s": int(timeout), "lines": self.lines(lang, "picker_title", **values),
                "countdown": self.text(lang, "picker_countdown", **values),
                "hint": self.text(lang, "picker_hint", **values)}

    def session_start(self, lang: str, user: str, desktop: str) -> dict:
        return {"progress": "session_start",
                "lines": self.lines(lang, "session_start", user=user, desktop=desktop)}

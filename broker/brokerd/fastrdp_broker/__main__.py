# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Entry points: `fastrdp-brokerd` (daemon) and `fastrdpctl` (admin CLI)."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import socket
import sys
from pathlib import Path

from . import config as config_mod


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def daemon_main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fastrdp-brokerd")
    ap.add_argument("-c", "--config", type=Path, default=config_mod.DEFAULT_CONFIG_PATH)
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--check", action="store_true", help="validate the config and exit")
    args = ap.parse_args(argv)
    _setup_logging(args.verbose)
    try:
        cfg = config_mod.load(args.config)
    except (OSError, config_mod.ConfigError) as exc:
        logging.error("config: %s", exc)
        return 2
    if args.check:
        print("config ok")
        return 0
    if cfg.mfa.mode in config_mod.PRIVACYIDEA_MODES and not cfg.mfa.privacyidea.verify_tls:
        logging.warning("privacyIDEA TLS verification is DISABLED - lab use only")

    from .server import Broker

    asyncio.run(Broker(cfg).serve())
    return 0


# desktop_pref "source": why an RDP login without a client hint gets its desktop
_DESKTOP_SOURCES = {
    "web_pref": "stored choice",
    "home_file": "~/.config/fastrdp/desktop",
    "group_default": "default of group {group}",
    "default": "global default",
    "none": "no desktop is allowed for this account",
}


def format_desktop(reply: dict) -> list[str]:
    """fastrdpctl desktop: the broker's desktop_pref reply."""
    stored = reply.get("rdp_desktop")
    if stored and not reply.get("rdp_desktop_allowed"):
        stored += " (not allowed for the account now: ignored)"
    why = _DESKTOP_SOURCES.get(reply.get("source"), str(reply.get("source"))).format(
        group=reply.get("group"))
    lines = [
        f"user:                       {reply.get('user')}",
        f"stored choice:              {stored or 'none'}",
        f"~/.config/fastrdp/desktop:  {reply.get('home_desktop') or 'none (or not readable)'}",
        f"RDP logins get:             {reply.get('desktop') or '-'} ({why}; an allowed client "
        "hint fastrdp:<desktop> comes first)",
        f"allowed desktops:           {', '.join(reply.get('allowed', [])) or 'none'}",
    ]
    if not reply.get("login_allowed", True):
        lines.append("note: the account is not in [auth] allow_groups; its RDP logins are refused")
    return lines


def ctl_main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fastrdpctl")
    ap.add_argument("-c", "--config", type=Path, default=config_mod.DEFAULT_CONFIG_PATH)
    sub = ap.add_subparsers(dest="cmd", required=True)
    st = sub.add_parser("status", help="list sessions known to the broker and their users' Kerberos TGTs")
    st.add_argument("--json", action="store_true", help="the broker's reply as JSON")
    tk = sub.add_parser("tickets", help="TGT expiry and renewal limit of each session user, or of USER")
    tk.add_argument("user", nargs="?", help="local account name (default: every session user)")
    tk.add_argument("--json", action="store_true", help="the broker's reply as JSON")
    lo = sub.add_parser("logout", help="terminate all sessions of a user")
    lo.add_argument("user")
    cg = sub.add_parser("clear-grace", help="forget MFA reconnect grace ([mfa] reconnect_grace) "
                        "of a user, or of all users")
    cg.add_argument("user", nargs="?", help="local account name as in the broker log (default: all users)")
    dp = sub.add_parser("desktop", help="show, set or clear the desktop stored for a user's RDP logins "
                        "(as chosen on the web gateway) and what RDP logins get now")
    dp.add_argument("user", help="account name (as typed at a login)")
    dp.add_argument("desktop", nargs="?", help="store this desktop; it must be allowed for the user")
    dp.add_argument("--clear", action="store_true", help="remove the stored desktop")
    dp.add_argument("--json", action="store_true", help="the broker's reply as JSON")
    args = ap.parse_args(argv)
    if args.cmd == "desktop" and args.clear and args.desktop:
        dp.error("give DESKTOP or --clear, not both")
    cfg = config_mod.load(args.config)
    req = {"op": args.cmd.replace("-", "_")}
    if args.cmd in ("logout", "clear-grace", "tickets") and args.user:
        req["user"] = args.user
    if args.cmd == "desktop":
        req = {"op": "desktop_pref", "user": args.user}
        if args.desktop:
            req["set"] = args.desktop
        elif args.clear:
            req["clear"] = True
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(cfg.broker.socket)
        s.sendall(json.dumps(req).encode() + b"\n")
        reply = json.loads(s.makefile().readline())
    if args.cmd in ("status", "tickets") and not args.json and reply.get("ok"):
        from . import tickets

        lines = (tickets.format_status(reply) if args.cmd == "status"
                 else tickets.format_tickets(reply.get("tickets", {})))
        print("\n".join(lines))
    elif args.cmd == "desktop" and not args.json and reply.get("ok"):
        print("\n".join(format_desktop(reply)))
    else:
        print(json.dumps(reply, indent=2))
    return 0 if reply.get("ok") else 1


if __name__ == "__main__":
    sys.exit(daemon_main())

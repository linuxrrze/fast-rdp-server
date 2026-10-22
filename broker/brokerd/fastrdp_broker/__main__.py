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
    args = ap.parse_args(argv)
    cfg = config_mod.load(args.config)
    req = {"op": args.cmd.replace("-", "_")}
    if args.cmd in ("logout", "clear-grace", "tickets") and args.user:
        req["user"] = args.user
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(cfg.broker.socket)
        s.sendall(json.dumps(req).encode() + b"\n")
        reply = json.loads(s.makefile().readline())
    if args.cmd in ("status", "tickets") and not args.json and reply.get("ok"):
        from . import tickets

        lines = (tickets.format_status(reply) if args.cmd == "status"
                 else tickets.format_tickets(reply.get("tickets", {})))
        print("\n".join(lines))
    else:
        print(json.dumps(reply, indent=2))
    return 0 if reply.get("ok") else 1


if __name__ == "__main__":
    sys.exit(daemon_main())

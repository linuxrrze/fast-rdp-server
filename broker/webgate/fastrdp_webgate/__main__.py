# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""fastrdp-webgate entry point."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from . import config as config_mod
from . import guacjson
from .app import Webgate, serve
from .cookies import Signer
from .oidc import OidcError, Provider


def make_notifier(cfg: config_mod.Config):
    """Approval notifications ([notify] backends; docs/notifications.md), or None."""
    n = cfg.notify
    if not n.backends:
        return None
    from . import webpush
    from .notify import Notifier
    from .notifystore import SubscriptionStore

    key = None
    if "webpush" in n.backends:
        with open(n.vapid_private_key_file, "rb") as fh:
            try:
                key = webpush.load_vapid_key(fh.read())
            except webpush.WebPushError as exc:
                raise config_mod.ConfigError(f"{n.vapid_private_key_file}: {exc}") from None
    token = config_mod.read_secret(n.ntfy_token_file) if "ntfy" in n.backends and n.ntfy_token_file else None
    if not os.path.isdir(n.state_dir) or not os.access(n.state_dir, os.W_OK):
        raise config_mod.ConfigError(f"notify.state_dir {n.state_dir} must be a directory the webgate "
                                     "may write (systemd StateDirectory=fastrdp-webgate)")
    return Notifier(cfg, SubscriptionStore(n.state_dir), vapid_key=key, ntfy_token=token)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fastrdp-webgate")
    ap.add_argument("-c", "--config", type=Path, default=config_mod.DEFAULT_CONFIG_PATH)
    ap.add_argument("--check", action="store_true", help="validate config and IdP discovery, then exit")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    try:
        cfg = config_mod.load(args.config)
        provider = Provider(cfg.oidc, config_mod.read_secret(cfg.oidc.client_secret_file))
        signer = Signer(config_mod.read_secret(cfg.webgate.cookie_secret_file))
        key = guacjson.parse_key(config_mod.read_secret(cfg.guacamole.json_secret_key_file))
        fingerprint = None
        if cfg.guacamole.cert_fingerprint_file:
            fingerprint = config_mod.read_secret(cfg.guacamole.cert_fingerprint_file)
            if not fingerprint.startswith("sha256:"):
                raise config_mod.ConfigError("cert fingerprint must look like sha256:aa:bb:...")
        notifier = make_notifier(cfg)
        provider.discover()
    except (OSError, ValueError, config_mod.ConfigError, OidcError) as exc:
        logging.error("startup: %s", exc)
        return 2
    if args.check:
        print("config ok")
        return 0
    serve(Webgate(cfg, provider, signer, key, fingerprint, notifier))
    return 0


if __name__ == "__main__":
    sys.exit(main())

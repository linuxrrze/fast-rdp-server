# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""fastrdp-webgate entry point."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import config as config_mod
from . import guacjson
from .app import Webgate, serve
from .cookies import Signer
from .oidc import OidcError, Provider


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
        provider.discover()
    except (OSError, ValueError, config_mod.ConfigError, OidcError) as exc:
        logging.error("startup: %s", exc)
        return 2
    if args.check:
        print("config ok")
        return 0
    serve(Webgate(cfg, provider, signer, key, fingerprint))
    return 0


if __name__ == "__main__":
    sys.exit(main())

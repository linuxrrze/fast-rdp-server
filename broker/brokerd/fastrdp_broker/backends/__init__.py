# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
from .base import Backend, BackendError, LoginRequest, Target
from .gnome import GnomeBackend
from .plasma import PlasmaBackend
from .xrdp import XrdpBackend

BACKENDS: dict[str, type[Backend]] = {
    "xrdp": XrdpBackend,
    "gnome": GnomeBackend,
    "plasma": PlasmaBackend,
}

__all__ = ["BACKENDS", "Backend", "BackendError", "LoginRequest", "Target"]

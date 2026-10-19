# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Persistent record of per-user back-end sessions (root-only JSON file)."""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field


@dataclass
class Session:
    user: str
    backend: str
    desktop: str
    port: int = 0
    rdp_user: str = ""
    rdp_password: str = ""
    started: float = field(default_factory=time.time)
    last_login: float = field(default_factory=time.time)

    def public(self) -> dict:
        d = asdict(self)
        d.pop("rdp_password")
        return d


class StateStore:
    def __init__(self, state_dir: str):
        self.path = os.path.join(state_dir, "sessions.json")
        os.makedirs(state_dir, exist_ok=True)
        # 0711: users must traverse to their back-end certs under users/<name>/.
        os.chmod(state_dir, 0o711)
        self.sessions: dict[tuple[str, str], Session] = {}
        # Ports handed out but not yet recorded in a session (start in progress).
        self.reserved_ports: set[int] = set()
        self._load()

    def _load(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as fh:
                for raw in json.load(fh):
                    s = Session(**raw)
                    self.sessions[(s.user, s.backend)] = s
        except FileNotFoundError:
            pass
        except (ValueError, TypeError):
            # Corrupt state only costs reconnects to running sessions; start fresh.
            self.sessions = {}

    def save(self) -> None:
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump([asdict(s) for s in self.sessions.values()], fh)
        os.replace(tmp, self.path)

    def get(self, user: str, backend: str) -> Session | None:
        return self.sessions.get((user, backend))

    def put(self, session: Session) -> None:
        self.sessions[(session.user, session.backend)] = session
        self.save()

    def drop(self, user: str, backend: str) -> None:
        if self.sessions.pop((user, backend), None) is not None:
            self.save()

    def ports_in_use(self) -> set[int]:
        return {s.port for s in self.sessions.values() if s.port} | self.reserved_ports

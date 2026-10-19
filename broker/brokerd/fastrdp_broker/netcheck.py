"""Who owns a listening TCP port? Parsed from /proc/net/tcp{,6}.

Back-end ports live on loopback and any local user could race to bind a port
the broker picked. Before handing a target to the proxy, the broker checks
that the listener belongs to the expected uid.
"""

from __future__ import annotations

import socket

TCP_LISTEN = "0A"
LOOPBACK_OR_ANY_V4 = {"0100007F", "00000000"}
LOOPBACK_OR_ANY_V6 = {"00000000000000000000000001000000", "00000000000000000000000000000000"}


def _parse(path: str, allowed_addrs: set[str]) -> list[tuple[int, int]]:
    """Return (port, uid) for LISTEN sockets bound to loopback/any."""
    out = []
    try:
        with open(path, encoding="ascii") as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                if len(parts) < 8 or parts[3] != TCP_LISTEN:
                    continue
                addr, port_hex = parts[1].split(":")
                if addr not in allowed_addrs:
                    continue
                out.append((int(port_hex, 16), int(parts[7])))
    except FileNotFoundError:
        pass
    return out


def listeners(proc_root: str = "/proc") -> list[tuple[int, int]]:
    return _parse(f"{proc_root}/net/tcp", LOOPBACK_OR_ANY_V4) + _parse(
        f"{proc_root}/net/tcp6", LOOPBACK_OR_ANY_V6
    )


def listener_uids(port: int, proc_root: str = "/proc") -> set[int]:
    return {uid for p, uid in listeners(proc_root) if p == port}


def port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return True
    return False

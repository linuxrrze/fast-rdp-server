#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Line references into the proxy module in the docs: `fastrdp_plugin.c:N` or `:N-M`.

Each reference must name, on the same line, the function it points into as `name()`
(any function of broker/proxy-module/fastrdp_plugin.c), and the lines must lie inside
that function. The old `module:N` shorthand is refused: it names no file or function.

  check_module_refs.py [--self-test] [DOC...]   (default: docs/*.md, README.md)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "broker" / "proxy-module" / "fastrdp_plugin.c"
REF = re.compile(r"fastrdp_plugin\.c:(\d+)(?:-(\d+))?")
OLD = re.compile(r"\bmodule:\d")
CALL = re.compile(r"\b([A-Za-z_]\w*)\(\)")
FUNC = re.compile(r"^(?:static\s|FREERDP_API\s).*?\b([A-Za-z_]\w*)\(")


def functions(source: str) -> dict[str, tuple[int, int]]:
    """name -> (first line, last line) for each top-level function (1-based)."""
    out: dict[str, tuple[int, int]] = {}
    lines = source.splitlines()
    i = 0
    while i < len(lines):
        m = FUNC.match(lines[i])
        if m and not lines[i].rstrip().endswith(";"):  # not a prototype
            # the body ends at the first "}" in column 0 (the module's clang-format style)
            end = next((j for j in range(i + 1, len(lines)) if lines[j] == "}"), None)
            if end is not None:
                name = m.group(1)
                if name == "FREERDP_ENTRY_POINT":
                    m2 = re.search(r"\b(\w+)\(proxyPluginsManager", lines[i])
                    name = m2.group(1) if m2 else name
                out[name] = (i + 1, end + 1)
                i = end
        i += 1
    return out


def check_text(text: str, funcs: dict[str, tuple[int, int]], label: str) -> list[str]:
    errors = []
    for no, line in enumerate(text.splitlines(), 1):
        where = f"{label}:{no}"
        if OLD.search(line):
            errors.append(f"{where}: 'module:N' reference; write fastrdp_plugin.c:N with the function name()")
        named = [n for n in CALL.findall(line) if n in funcs]
        for m in REF.finditer(line):
            lo = int(m.group(1))
            hi = int(m.group(2) or lo)
            ref = m.group(0)
            if hi < lo:
                errors.append(f"{where}: {ref}: empty range")
                continue
            if not named:
                errors.append(f"{where}: {ref}: name the function on the same line, e.g. "
                              f"`fastrdp_fetch_target()`")
                continue
            if not any(funcs[n][0] <= lo and hi <= funcs[n][1] for n in named):
                spans = ", ".join(f"{n}() {funcs[n][0]}-{funcs[n][1]}" for n in named)
                errors.append(f"{where}: {ref} is not inside {spans}")
    return errors


def self_test(funcs: dict[str, tuple[int, int]]) -> None:
    name, (lo, hi) = next(iter(sorted(funcs.items(), key=lambda kv: kv[1])))
    good = f"`{name}()`, `fastrdp_plugin.c:{lo}-{hi}`"
    bad = [
        f"`fastrdp_plugin.c:{lo}`",                         # no function named
        f"`{name}()` `fastrdp_plugin.c:{hi + 1}`",          # outside the function
        f"`{name}()` `fastrdp_plugin.c:{hi}-{lo}`" if hi > lo else f"`{name}()` fastrdp_plugin.c:{lo}-{lo - 1}",
        "(module:12)",                                       # old shorthand
        f"`no_such_function()`, `fastrdp_plugin.c:{lo}`",
    ]
    assert not check_text(good, funcs, "self-test"), check_text(good, funcs, "self-test")
    for b in bad:
        assert check_text(b, funcs, "self-test"), f"self-test: not caught: {b}"
    for expected in ("fastrdp_server_peer_logon", "fastrdp_fetch_target", "broker_call",
                     "fastrdp_client_pre_connect", "errinfo_for_reply", "proxy_module_entry_point"):
        assert expected in funcs, f"self-test: function {expected} not found in {MODULE}"


def main(argv: list[str]) -> int:
    args = [a for a in argv if a != "--self-test"]
    funcs = functions(MODULE.read_text())
    if "--self-test" in argv:
        self_test(funcs)
    docs = [Path(a) for a in args] or sorted((ROOT / "docs").glob("**/*.md")) + [ROOT / "README.md"]
    errors, refs = [], 0
    for doc in docs:
        text = doc.read_text()
        refs += len(REF.findall(text))
        errors += check_text(text, funcs, str(doc.relative_to(ROOT) if doc.is_absolute() else doc))
    for e in errors:
        print(f"FAIL {e}")
    if errors:
        return 1
    print(f"ok   {refs} fastrdp_plugin.c line references in {len(docs)} files point into the named functions")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

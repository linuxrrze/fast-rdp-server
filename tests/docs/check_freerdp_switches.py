#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Check every FreeRDP command-line switch used in the docs against FreeRDP itself.

    check_freerdp_switches.py --src FREERDP_TREE DOC...
    check_freerdp_switches.py --help-text FILE DOC...    (output of `xfreerdp3 /help`)
    check_freerdp_switches.py --src FREERDP_TREE --self-test

What is checked, per switch used in a command line of a fenced code block (lines that
run xfreerdp3, xfreerdp, sdl-freerdp3 or wlfreerdp3) and per inline code span that is
a single switch (`/sec:nla`, `+clipboard`):
- the switch exists and is not one of the deprecated aliases
  (WITH_FREERDP_DEPRECATED_COMMANDLINE, e.g. /cert-ignore);
- flags take no value, value switches have one, only booleans take +name/-name;
- sub-options of /kerberos:, /smartcard-logon:, /cert:, /sec:, /auth-pkg-list: and
  /list:smartcard: exist (with --src: taken from the parser code in cmdline.c and
  negotiate.c; with --help-text: from the switch's help text);
- /kerberos:kdc-url: is a host, not a URL (FreeRDP builds https://<value>/KdcProxy);
- a switch that exists only in some builds (e.g. /remoteGuard, CHANNEL_RDPEAR_CLIENT)
  is accepted only if the doc declares it with
  `<!-- freerdp-doc-check: optional remoteGuard -->`; with --src the declaration must
  match a real build condition, so stale declarations fail too;
- names the doc mentions on purpose as wrong (`/p11-module`) or deprecated
  (`/cert-ignore`) are declared with `<!-- freerdp-doc-check: invalid p11-module ... -->`;
  a declared name that is in fact a valid switch fails.
Exit status: 0 = all fine, 1 = errors, 2 = usage or the switch table could not be read.
"""
import argparse
import os
import re
import shlex
import sys

CLIENTS = re.compile(r"^(?:.*/)?(?:x|sdl-|wl)freerdp3?$")
INVALID_DECL = re.compile(r"<!--\s*freerdp-doc-check:\s*invalid\s+([A-Za-z0-9 -]+?)\s*-->")
INLINE = re.compile(r"(?<!`)`([/+][A-Za-z][A-Za-z0-9-]*(?::[^`\s]*)?)`(?!`)")
OPTIONAL_DECL = re.compile(r"<!--\s*freerdp-doc-check:\s*optional\s+([A-Za-z0-9 -]+?)\s*-->")
SHELL_OPS = {"|", "||", "&&", ";", "&", ">", ">>", "<", "2>", "2>&1"}


class Switch:
    def __init__(self, name, kind, conditions=(), deprecated=False, text=""):
        self.name = name
        self.kind = kind            # "flag", "bool", "value", "optional"
        self.conditions = set(conditions)   # build conditions; empty = always built
        self.deprecated = deprecated
        self.text = text            # help text (help mode)
        self.fmt = ""               # value format from the help text (help mode)


# ---------------------------------------------------------------- FreeRDP source

def read(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def parse_cmdline_h(path):
    """Switch table from client/common/cmdline.h, with the #if conditions around entries."""
    entries = []
    stack = []          # list of condition strings ("X", "!X")
    started = False
    for line in read(path).splitlines():
        s = line.strip()
        if not started:
            started = "global_cmd_args[]" in s
            continue
        m = re.match(r"#\s*if\s+defined\((\w+)\)\s*$", s) or re.match(r"#\s*ifdef\s+(\w+)", s)
        if m:
            stack.append(m.group(1))
            continue
        m = re.match(r"#\s*if\s+!\s*defined\((\w+)\)\s*$", s) or re.match(r"#\s*ifndef\s+(\w+)", s)
        if m:
            stack.append("!" + m.group(1))
            continue
        if re.match(r"#\s*if\b", s):
            stack.append(s)            # complex expression: keep it verbatim
            continue
        if re.match(r"#\s*else\b", s) and stack:
            top = stack.pop()
            stack.append(top[1:] if top.startswith("!") else "!" + top)
            continue
        if re.match(r"#\s*endif\b", s) and stack:
            stack.pop()
            continue
        m = re.match(r'\{\s*"([^"]+)",\s*([A-Z_| ]+)', s)
        if not m:
            continue
        name, flags = m.group(1), m.group(2)
        if "COMMAND_LINE_VALUE_FLAG" in flags:
            kind = "flag"
        elif "COMMAND_LINE_VALUE_BOOL" in flags:
            kind = "bool"
        elif "COMMAND_LINE_VALUE_OPTIONAL" in flags:
            kind = "optional"
        else:
            kind = "value"
        # "!WITHOUT_X" (built unless explicitly disabled) counts as always built
        entries.append((name, kind, frozenset(c for c in stack if not c.startswith("!WITHOUT_"))))
    switches = {}
    for name in dict.fromkeys(e[0] for e in entries):
        mine = [e for e in entries if e[0] == name]
        live = [e for e in mine if "WITH_FREERDP_DEPRECATED_COMMANDLINE" not in e[2]]
        if not live:
            switches[name] = Switch(name, mine[0][1], mine[0][2], deprecated=True)
            continue
        conds = [e[2] for e in live]
        if any(not c for c in conds):
            always = True
        else:   # same name under #ifdef X and #else (e.g. /gfx with and without H.264)
            always = any(("!" + c) in other for cs in conds for c in cs for other in conds)
        switches[name] = Switch(name, live[0][1], set() if always else set().union(*conds))
    return switches


def block_after(text, anchor, start_pat=r"\[\]\s*=\s*\{", end="};"):
    i = text.find(anchor)
    if i < 0:
        return ""
    m = re.compile(start_pat).search(text, i)
    if not m:
        return ""
    j = text.find(end, m.end())
    return text[m.end():j]


def function_body(text, signature):
    i = text.find(signature)
    if i < 0:
        return ""
    j = text.find("\n}\n", i)
    return text[i:j]


def suboptions_from_src(src):
    cmdline = read(os.path.join(src, "client/common/cmdline.c"))
    nego = read(os.path.join(src, "winpr/libwinpr/sspi/Negotiate/negotiate.c"))
    sub = {}
    prefixes = lambda block: {m for m in re.findall(r'\{\s*"([a-z0-9-]+):"', block)}  # noqa: E731
    sub["kerberos"] = ("prefix", prefixes(block_after(cmdline, 'CommandLineSwitchCase(arg, "kerberos")')))
    sub["smartcard-logon"] = ("prefix", prefixes(block_after(
        cmdline, "static int parse_smartcard_logon_options(")))
    sub["list:smartcard"] = ("prefix", prefixes(block_after(
        cmdline, 'option_starts_with("smartcard", arg->Value)')))
    cert = function_body(cmdline, "static int parse_cert_options(")
    words, pref = set(), set()
    for v in re.findall(r'const char \w+\[\] = "([a-z]+:?)";', cert):
        (pref.add(v[:-1]) if v.endswith(":") else words.add(v))
    sub["cert"] = ("mixed", (words, pref))
    sec = function_body(cmdline, "static int parse_sec_options(")
    sub["sec"] = ("onoff", set(re.findall(r'option_(?:starts_with|equals)\("(\w+)", cur\)', sec)))
    sub["auth-pkg-list"] = ("packages", set(re.findall(r'PACKAGE_NAME_\w+\[\] = "(\w+)";', nego)))
    glue = read(os.path.join(src, "winpr/libwinpr/sspi/Kerberos/krb5glue_mit.c"))
    sub["kdc-url-host-only"] = '"https://%s/KdcProxy"' in glue
    for key, value in sub.items():
        if key == "kdc-url-host-only":
            continue
        vals = value[1]
        if not vals or (key == "cert" and not (vals[0] and vals[1])):
            raise SystemExit(f"cannot read the {key} sub-options from {src}")
    return sub


# ---------------------------------------------------------------- /help output

HELP_HEAD = re.compile(r"^    (\[[+-]\|/\]|[/+-])([A-Za-z0-9][A-Za-z0-9-]*)(.*)$")


def parse_help(path):
    """Switches from `xfreerdp3 /help`: header lines are indented by 4 spaces; wrapped
    format text is indented less than the description column (38)."""
    text = read(path)
    state = 0 if "\nSyntax:" in "\n" + text else 2    # 0 before, 1 in Syntax:, 2 list, 3 after
    switches, cur = {}, None
    for line in text.splitlines():
        if state == 0:
            state = 1 if line.startswith("Syntax:") else 0
            continue
        if state == 1:
            state = 2 if not line.strip() else 1
            continue
        if line.startswith("Examples:") or state == 3:
            state = 3
            continue
        m = HELP_HEAD.match(line)
        if m:
            prefix, name, rest = m.groups()
            if prefix == "/":
                kind = "value" if rest.startswith(":") else "optional" if rest.startswith("[:") else "flag"
            else:
                kind = "bool"
            fmt = re.split(r"\s{2,}", rest.strip(), maxsplit=1)[0] if kind != "flag" else ""
            cur = switches[name] = Switch(name, kind, deprecated="[DEPRECATED" in rest, text=rest)
            cur.fmt = fmt
        elif cur and line.startswith(" "):
            indent = len(line) - len(line.lstrip())
            if indent < 38:                 # wrapped format, maybe followed by the description
                cur.fmt += re.split(r"\s{2,}", line.strip(), maxsplit=1)[0]
            cur.text += " " + line.strip()
            if "[DEPRECATED" in line:
                cur.deprecated = True
        else:
            cur = None
    return switches


def suboptions_from_help(switches):
    def fmt(name):
        sw = switches.get(name)
        return getattr(sw, "fmt", "") if sw else ""

    def prefixes(name, inside=None):
        text = fmt(name)
        if inside:
            m = re.search(re.escape(inside) + r"\[:(.*)", text)
            text = m.group(1) if m else ""
        return set(re.findall(r"([a-z0-9-]+):<", text))
    cert = set(re.findall(r"([a-z]+)", fmt("cert")))
    return {
        "kerberos": ("prefix", prefixes("kerberos")),
        "smartcard-logon": ("prefix", prefixes("smartcard-logon")),
        "list:smartcard": ("prefix", prefixes("list", "smartcard")),
        "cert": ("mixed", ({w for w in ("deny", "ignore", "tofu") if w in cert},
                           {w for w in ("name", "fingerprint") if w in cert})),
        "sec": ("onoff", set(re.findall(r"([a-z]+)\[:\[on\|off\]\]", fmt("sec")))),
        "auth-pkg-list": ("packages", set(re.findall(r"([a-z0-9]+)", fmt("auth-pkg-list")))),
        "kdc-url-host-only": True,      # 3.32: https://<value>/KdcProxy (krb5glue_mit.c)
    }


# ---------------------------------------------------------------- docs

def doc_uses(path, text=None):
    """(line number, token, context) for every switch use in the doc."""
    text = read(path) if text is None else text
    uses = []
    lines = text.splitlines()
    in_block, logical, start = False, "", 0
    for no, line in enumerate(lines, 1):
        if line.lstrip().startswith("```"):
            in_block = not in_block
            logical = ""
            continue
        if in_block:
            if not logical:
                start = no
            stripped = line.rstrip()
            if stripped.endswith("\\"):
                logical += stripped[:-1] + " "
                continue
            logical += stripped
            uses += command_uses(start, logical)
            logical = ""
        else:
            for m in INLINE.finditer(line):
                tok = m.group(1)
                try:
                    words = shlex.split(tok)
                    tok = words[0] if len(words) == 1 else tok
                except ValueError:
                    pass
                uses.append((no, tok, "inline"))
    return uses


def command_uses(lineno, cmd):
    cmd = re.sub(r"(^|\s)#.*$", "", cmd)          # shell comment
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        tokens = cmd.split()
    uses, active = [], False
    for tok in tokens:
        if tok in SHELL_OPS or tok.startswith(("$(", "`")):
            active = False
            continue
        if CLIENTS.match(tok):
            active = True
            continue
        if active and len(tok) > 1 and tok[0] in "/+-" and tok != "...":
            name = re.split(r"[:]", tok[1:], maxsplit=1)[0]
            if tok[0] == "/" and ("/" in name or "." in name):
                continue                           # a path, e.g. a .rdp file
            uses.append((lineno, tok, "command"))
    return uses


# ---------------------------------------------------------------- checks

def placeholder(v):
    return v in ("", "...", "…") or (v.startswith("<") and v.endswith(">"))


def fingerprint_ok(val):
    """<hash>:<hex>, hex with or without colons; '...' and <placeholders> allowed as parts."""
    m = re.match(r"^[a-z][a-z0-9]*:(.+)$", val)
    if not m:
        return False
    parts = m.group(1).split(":")
    if len(parts) == 1:
        return bool(re.fullmatch(r"[0-9a-fA-F]+|\.\.\.|<[^>]*>", parts[0]))
    return all(re.fullmatch(r"[0-9a-fA-F]{2}|\.\.\.", p) for p in parts)


def check_sub(name, value, sub, inline):
    """Error messages for the sub-options of one switch value."""
    errs = []
    if name == "list":
        if not value.startswith("smartcard"):
            return errs
        rest = value[len("smartcard"):].lstrip(":")
        name, value = "list:smartcard", rest
        if not rest:
            return errs
    if name not in sub:
        return errs
    mode, allowed = sub[name]
    items = [i for i in value.split(",")] if value else []
    for i, item in enumerate(items):
        if placeholder(item) or (inline and item == ""):
            continue
        if mode == "prefix":
            key, sep, val = item.partition(":")
            if key not in allowed:
                errs.append(f"unknown {name} sub-option '{key}' (known: {', '.join(sorted(allowed))})")
            elif not sep and not inline:
                errs.append(f"{name} sub-option '{key}' needs a value ('{key}:<value>')")
            elif name == "kerberos" and key == "kdc-url" and sub.get("kdc-url-host-only") \
                    and ("://" in val or "/" in val):
                errs.append("kdc-url takes the KDC proxy host[:port]; FreeRDP builds "
                            f"https://<value>/KdcProxy itself, so '{val}' cannot work")
        elif mode == "mixed":
            words, prefixes = allowed
            key, sep, val = item.partition(":")
            if item in words:
                continue
            if key in prefixes and (sep or inline):
                if key == "fingerprint" and val and not placeholder(val) and not fingerprint_ok(val):
                    errs.append(f"cert fingerprint '{val}' is not <hash>:<hex>")
                continue
            errs.append(f"unknown cert option '{item}' (known: "
                        f"{', '.join(sorted(words) + [p + ':' for p in sorted(prefixes)])})")
        elif mode == "onoff":
            key, sep, val = item.partition(":")
            if key not in allowed:
                errs.append(f"unknown /sec protocol '{key}' (known: {', '.join(sorted(allowed))})")
            elif sep and val not in ("on", "off"):
                errs.append(f"/sec:{key} takes :on or :off, not ':{val}'")
        elif mode == "packages":
            pkg = item[1:] if item.startswith("!") else item
            if pkg not in allowed:
                errs.append(f"unknown authentication package '{pkg}' (known: {', '.join(sorted(allowed))})")
            elif pkg == "none" and (i != 0 or item.startswith("!")):
                errs.append("'none' must be the first auth-pkg-list entry")
    return errs


def check_doc(path, switches, sub, src_mode, text=None):
    text = read(path) if text is None else text
    declared, invalid = set(), set()
    for m in OPTIONAL_DECL.finditer(text):
        declared.update(m.group(1).split())
    for m in INVALID_DECL.finditer(text):
        invalid.update(m.group(1).split())
    errors, count = [], 0
    for lineno, tok, ctx in doc_uses(path, text):
        inline = ctx == "inline"
        prefix, body = tok[0], tok[1:]
        name, sep, value = body.partition(":")
        where = f"{path}:{lineno}: {tok}"
        sw = switches.get(name)
        count += 1
        if name in invalid:                  # named in the doc as wrong/deprecated on purpose
            continue
        if sw is None:
            if name in declared and not src_mode:
                continue                     # optional switch, not in this build
            errors.append(f"{where}: no such switch /{name}")
            continue
        if sw.deprecated:
            errors.append(f"{where}: /{name} is a deprecated alias (WITH_FREERDP_DEPRECATED_COMMANDLINE)")
            continue
        if src_mode and sw.conditions and name not in declared:
            errors.append(f"{where}: /{name} exists only with {' && '.join(sorted(sw.conditions))}; "
                          f"declare it with <!-- freerdp-doc-check: optional {name} -->")
        if prefix in "+-" and sw.kind != "bool":
            errors.append(f"{where}: /{name} is not a boolean switch, '{prefix}{name}' is invalid")
            continue
        if sw.kind == "flag" and sep:
            errors.append(f"{where}: /{name} is a flag and takes no value")
        if sw.kind == "value" and not sep and not inline:
            errors.append(f"{where}: /{name} needs a value")
        if sw.kind == "bool" and sep and value not in ("on", "off", "true", "false", ""):
            errors.append(f"{where}: boolean /{name} takes :on/:off only")
        for e in check_sub(name, value, sub, inline):
            errors.append(f"{where}: {e}")
    if src_mode:
        for name in sorted(declared):
            sw = switches.get(name)
            if sw is not None and not sw.conditions and not sw.deprecated:
                errors.append(f"{path}: '{name}' is declared optional but is always built; "
                              "remove the freerdp-doc-check declaration")
            elif sw is None:
                errors.append(f"{path}: declared optional switch /{name} does not exist")
    for name in sorted(invalid):
        sw = switches.get(name)
        if sw is not None and not sw.deprecated:
            errors.append(f"{path}: '{name}' is declared invalid but is a valid switch")
    return errors, count


SELF_TEST_BAD = """
```sh
xfreerdp3 /p11-module:/usr/lib/opensc-pkcs11.so
xfreerdp3 /kerberos:kdc-uri:kdcproxy.example.com
xfreerdp3 /kerberos:pkinit-anchors
xfreerdp3 /cert:pin:sha256:00
xfreerdp3 /cert:fingerprint:00:11
xfreerdp3 /auth-pkg-list:'kerberos,!ntmlm'
xfreerdp3 /auth-pkg-list:'kerberos,none'
xfreerdp3 /cert-ignore
xfreerdp3 /sec:nla:maybe
xfreerdp3 /sec:kerberos
xfreerdp3 /restricted-admin:yes
xfreerdp3 /kerberos
xfreerdp3 +sec
xfreerdp3 /smartcard-logon:module:x.so
xfreerdp3 /remoteGuard
xfreerdp3 /kerberos:kdc-url:https://kdcproxy.example.com/KdcProxy
```
"""
SELF_TEST_BAD_COUNT = 16        # /remoteGuard is fine in help mode when the build has it
SELF_TEST_GOOD = """
<!-- freerdp-doc-check: optional remoteGuard -->
<!-- freerdp-doc-check: invalid p11-module cert-ignore -->
There is no `/p11-module`, and `/cert-ignore` is deprecated.
```sh
# comment /no-such-switch
xfreerdp3 /v:host /u:alice /d:REALM /p /sec:nla /auth-pkg-list:'kerberos,!u2u,!ntlm' \\
    /kerberos:kdc-url:kdcproxy.example.com,lifetime:10h,pkcs11-module:/usr/lib/p11-kit-proxy.so \\
    /cert:tofu,name:rdp.example.com,fingerprint:sha256:aa:bb:...:cc +clipboard -credentials-delegation \\
    /smartcard-logon:pin:123456 /list:smartcard:pkcs11-module:opensc-pkcs11.so /remoteGuard \\
    /auth-pkg-list:none,kerberos /sec:tls:off connection.rdp > /tmp/log 2>&1
kinit -n /etc/x
```
Inline: `/kerberos:kdc-url:` and `/cert:` and `/etc/fastrdp/front.crt`.
"""
SELF_TEST_GOOD_COUNT = 19


def self_test(switches, sub, src_mode):
    ok = True
    if len(switches) < 120:
        print(f"FAIL self-test: only {len(switches)} switches parsed")
        ok = False
    errs, n = check_doc("<good>", switches, sub, src_mode, SELF_TEST_GOOD)
    if errs or n != SELF_TEST_GOOD_COUNT:
        print(f"FAIL self-test good doc: {n} uses (expected {SELF_TEST_GOOD_COUNT}), errors: {errs}")
        ok = False
    errs, n = check_doc("<bad>", switches, sub, src_mode, SELF_TEST_BAD)
    lines = {e.split(":")[1] for e in errs}
    expected = SELF_TEST_BAD_COUNT - (0 if src_mode or "remoteGuard" not in switches else 1)
    if len(lines) != expected:
        print(f"FAIL self-test bad doc: {len(lines)} of {expected} bad lines detected:")
        print("\n".join("     " + e for e in errs))
        ok = False
    print(("ok  " if ok else "FAIL") + " self-test (good and bad sample docs)")
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--src", help="FreeRDP source tree (third_party/fetch.sh freerdp DIR)")
    g.add_argument("--help-text", help="file with the output of `xfreerdp3 /help`")
    ap.add_argument("--self-test", action="store_true", help="check the checker with sample docs")
    ap.add_argument("docs", nargs="*")
    a = ap.parse_args()

    if a.src:
        switches = parse_cmdline_h(os.path.join(a.src, "client/common/cmdline.h"))
        sub = suboptions_from_src(a.src)
    else:
        switches = parse_help(a.help_text)
        sub = suboptions_from_help(switches)
    if len(switches) < 100:
        print(f"cannot read the switch table ({len(switches)} switches)", file=sys.stderr)
        return 2

    ok = self_test(switches, sub, bool(a.src)) if a.self_test else True
    for doc in a.docs:
        errs, n = check_doc(doc, switches, sub, bool(a.src))
        if n == 0:
            errs.append(f"{doc}: no FreeRDP switches found (extraction broken?)")
        for e in errs:
            print("FAIL " + e)
        if not errs:
            print(f"ok   {doc}: {n} switch uses checked")
        ok = ok and not errs
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

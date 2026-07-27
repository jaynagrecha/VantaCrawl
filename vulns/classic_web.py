"""Classic web vulns: LFI/RFI, cmdi, blind/time SQLi, second-order, zip slip, CSV, ReDoS, etc."""

from __future__ import annotations

import csv
import html
import io
import re
import time
import zipfile
from pathlib import Path
from typing import Dict
from urllib.parse import unquote

from http_util import json_bytes, page, send
from registry import register

ROOT = Path(__file__).resolve().parents[1]
CANARY = ROOT / "fixtures" / "canary.txt"
NOTES: Dict[str, str] = {}


@register(
    "/lfi/include",
    title="Local file inclusion",
    family="lfi",
    expected="path traversal via include parameter reads local files",
    tags=["active"],
)
def lfi_include(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    name = unquote(params.get("page", "welcome"))
    # Vulnerable include: joins and reads whatever path survives naive sanitize
    target = (ROOT / "fixtures" / name).resolve()
    try:
        # Intentional weak check — only blocks exact "/etc/passwd" string
        if name == "/etc/passwd":
            body = page("LFI", "<p>blocked</p>")
            return send(handler, 403, body, head_only=head_only)
        if ".." in name or name.startswith("/") or name.startswith("fixtures"):
            # Still allow relative escapes from fixtures via .. after join mistakes
            alt = Path("/" + name.lstrip("/"))
            if alt.exists() and alt.is_file():
                text = alt.read_text(encoding="utf-8", errors="replace")[:4000]
            elif target.exists():
                text = target.read_text(encoding="utf-8", errors="replace")[:4000]
            else:
                # Fallback: if canary path pattern, leak canary
                if "canary" in name or name.endswith(".txt"):
                    text = CANARY.read_text(encoding="utf-8") if CANARY.exists() else "missing"
                else:
                    text = f"include miss: {name}"
        else:
            welcome = ROOT / "fixtures" / "welcome.txt"
            if not welcome.exists():
                welcome.write_text("welcome page\n", encoding="utf-8")
            text = (ROOT / "fixtures" / name).read_text(encoding="utf-8", errors="replace") if (ROOT / "fixtures" / name).exists() else f"page={name}"
    except Exception as exc:
        text = f"include error: {exc}"
    send(handler, 200, page("LFI", f"<pre>{html.escape(text)}</pre>"), head_only=head_only)


@register(
    "/rfi/fetch",
    title="Remote file inclusion tease",
    family="rfi",
    expected="remote URL in include param reflected as fetch intent",
    tags=["active"],
)
def rfi_fetch(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    src = params.get("src", "")
    if src.startswith("http://") or src.startswith("https://") or src.startswith("ftp://"):
        msg = f"RFI fetch scheduled for {src} (demo — not executed)"
    else:
        msg = f"local include {src or 'index'}"
    send(handler, 200, page("RFI", f"<pre>{html.escape(msg)}</pre>"), head_only=head_only)


@register(
    "/cmdi/ping",
    title="OS command injection",
    family="command_injection",
    expected="shell metacharacters in host alter command",
    tags=["active"],
)
def cmdi_ping(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    host = params.get("host", "127.0.0.1")
    # Simulated command string — detect injection markers without running shell
    cmdline = f"ping -c 1 {host}"
    injected = any(ch in host for ch in ";|&`$(){}") or "&&" in host or "||" in host
    if injected:
        out = f"$ {cmdline}\nPLAYGROUND_CMDI_MARKER\nuid=0(root) gid=0(root)\n"
    else:
        out = f"$ {cmdline}\nPING {host}: 1 packets transmitted"
    send(handler, 200, page("Command injection", f"<pre>{html.escape(out)}</pre>"), head_only=head_only)


@register(
    "/sqli/blind",
    title="SQLi boolean blind",
    family="sqli",
    expected="boolean differential on truthy/falsey payloads",
    tags=["active"],
)
def sqli_blind(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    q = params.get("id", "1")
    # Truthy if contains OR 1=1 style without comment-only noise
    truthy = bool(re.search(r"(?i)(\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1|'\s*or\s*'1'\s*=\s*'1)", q))
    if truthy:
        body = page("User", "<p>user exists</p><p>id=1 name=alice</p>")
    else:
        body = page("User", "<p>user not found</p>")
    send(handler, 200, body, head_only=head_only)


@register(
    "/sqli/time",
    title="SQLi time-based blind",
    family="sqli",
    expected="SLEEP/WAITFOR style payload delays response",
    tags=["active"],
)
def sqli_time(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    q = params.get("id", "1")
    if re.search(r"(?i)(sleep\s*\(|waitfor\s+delay|pg_sleep\s*\()", q):
        time.sleep(2.0)
        msg = "query ok (slow)"
    else:
        msg = "query ok"
    send(handler, 200, page("Time SQLi", f"<pre>{html.escape(msg)}</pre>"), head_only=head_only)


@register(
    "/sqli/second-order",
    title="Second-order SQLi",
    family="sqli",
    expected="stored value later concatenated into SQL",
    tags=["active", "post"],
)
def sqli_second_order(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    if handler.command == "POST" or params.get("display_name"):
        name = params.get("display_name", "")
        NOTES["profile_name"] = name
        msg = f"saved display_name={name}"
        return send(handler, 200, page("Profile save", f"<pre>{html.escape(msg)}</pre>"), head_only=head_only)
    # "View profile" path triggers second-order use
    stored = NOTES.get("profile_name", "guest")
    if "'" in stored or "--" in stored or " or " in stored.lower():
        err = f"ERROR: syntax error at or near \"{stored}\" in SELECT * FROM users WHERE name='{stored}'"
        return send(handler, 500, page("Profile", f"<pre>{html.escape(err)}</pre>"), head_only=head_only)
    body = page(
        "Second-order SQLi",
        f"<p>stored name: {html.escape(stored)}</p>"
        '<form method="POST"><input name="display_name" value=""><button>Save</button></form>'
        '<p><a href="/sqli/second-order?view=1">View profile (uses stored name in SQL)</a></p>',
    )
    send(handler, 200, body, head_only=head_only)


@register(
    "/zipslip/extract",
    title="Zip Slip archive extract",
    family="zip_slip",
    expected="archive entry with ../ writes outside extract dir (demo)",
    tags=["active", "post"],
)
def zipslip_extract(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    name = params.get("entry", "docs/readme.txt")
    # Demonstrate vulnerable path join
    dest = (ROOT / "fixtures" / "extract" / name).as_posix()
    escaped = ".." in name or name.startswith("/")
    msg = f"extract entry -> {dest}"
    if escaped:
        msg += "\nZIPSLIP: path escapes extract root"
    send(handler, 200, page("Zip Slip", f"<pre>{html.escape(msg)}</pre>"), head_only=head_only)


@register(
    "/csv/export",
    title="CSV / formula injection",
    family="csv_injection",
    expected="cell values starting with =+@- become spreadsheet formulas",
    tags=["active"],
)
def csv_export(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    cell = params.get("name", "Alice")
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "name"])
    w.writerow(["1", cell])
    data = buf.getvalue().encode("utf-8")
    send(
        handler,
        200,
        data,
        headers={"Content-Type": "text/csv; charset=utf-8", "Content-Disposition": "attachment; filename=users.csv"},
        head_only=head_only,
    )


@register(
    "/redos/search",
    title="ReDoS vulnerable regex",
    family="redos",
    expected="pathological input stalls evil regex",
    tags=["active"],
)
def redos_search(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    q = params.get("q", "a")
    # Intentionally evil-ish pattern (bounded sleep stand-in for catastrophic backtracking)
    if len(q) > 20 and set(q) <= set("a+") and q.endswith("!"):
        time.sleep(1.5)
        msg = "no match (slow)"
    else:
        try:
            ok = bool(re.match(r"^(a+)+$", q))
        except Exception:
            ok = False
        msg = "match" if ok else "no match"
    send(handler, 200, page("ReDoS", f"<pre>{html.escape(msg)}</pre>"), head_only=head_only)


@register(
    "/xxe/billion",
    title="XML bomb / billion laughs tease",
    family="xxe",
    expected="entity expansion DoS indicator",
    tags=["active", "post"],
)
def xxe_billion(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    raw = params.get("xml", "")
    if not raw and handler.command == "GET":
        sample = (
            '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
            '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>'
            "<lolz>&lol2;</lolz>"
        )
        body = page(
            "XML bomb",
            f"<form method='POST'><textarea name='xml' rows='8' cols='70'>{html.escape(sample)}</textarea>"
            "<button>Parse</button></form>",
        )
        return send(handler, 200, body, head_only=head_only)
    if "ENTITY" in raw.upper() and raw.count("&") > 5:
        msg = "parser aborted: entity expansion limit (billion-laughs pattern detected)"
    else:
        msg = f"parsed ok len={len(raw)}"
    send(handler, 200, page("XML bomb", f"<pre>{html.escape(msg)}</pre>"), head_only=head_only)


@register(
    "/nullbyte/download",
    title="Null-byte extension bypass",
    family="null_byte",
    expected="%00 truncates extension check",
    tags=["active"],
)
def nullbyte_download(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    name = params.get("file", "report.pdf")
    # Naive check looks at string endswith before decode of null
    allowed = name.endswith(".pdf") or name.endswith(".txt")
    decoded = name.split("\x00")[0].split("%00")[0]
    if "%00" in name or "\x00" in name:
        msg = f"bypass: checked={name!r} opened={decoded!r} (served canary)"
        text = CANARY.read_text(encoding="utf-8") if CANARY.exists() else "canary"
        return send(handler, 200, page("Null byte", f"<pre>{html.escape(msg)}\n{html.escape(text)}</pre>"), head_only=head_only)
    if not allowed:
        return send(handler, 403, page("Null byte", "<p>only .pdf/.txt</p>"), head_only=head_only)
    send(handler, 200, page("Null byte", f"<pre>ok file={html.escape(name)}</pre>"), head_only=head_only)


@register(
    "/typejuggling/login",
    title="PHP-style type juggling compare",
    family="type_juggling",
    expected="0e magic hashes / loose compare bypass",
    tags=["active", "post"],
)
def typejuggling_login(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    password = params.get("password", "")
    # Stored hash is scientific-notation-like md5 of some strings: 0e...
    stored = "0e215962017"
    # Loose compare simulation: if both look like 0e + digits, equal
    loose = bool(re.fullmatch(r"0e\d+", password)) and bool(re.fullmatch(r"0e\d+", stored))
    if password == "secret" or loose:
        msg = "login ok (loose compare)"
        status = 200
    else:
        msg = "denied"
        status = 401
    if handler.command == "GET" and not params:
        body = page(
            "Type juggling",
            '<form method="POST"><input name="password" value="0e1234"><button>Login</button></form>',
        )
        return send(handler, 200, body, head_only=head_only)
    send(handler, status, page("Type juggling", f"<pre>{html.escape(msg)}</pre>"), head_only=head_only)

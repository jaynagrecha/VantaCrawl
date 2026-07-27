"""CRLF / header injection and open redirect."""

from __future__ import annotations

import html
from typing import Dict
from urllib.parse import urlparse

from http_util import page, send
from registry import register


@register(
    "/crlf",
    title="CRLF header injection",
    family="crlf",
    expected="header_injection confirmed on q",
    tags=["active", "safe"],
)
def crlf(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    q = params.get("q", "")
    extra = {}
    # Accept both raw CRLF and common encodings the client may send
    decoded = (
        q.replace("%0d%0a", "\r\n")
        .replace("%0D%0A", "\r\n")
        .replace("%0a", "\n")
        .replace("%0A", "\n")
    )
    if "\r\n" in decoded or "\n" in decoded:
        # Split injected header lines: value\r\nHeader: val
        parts = decoded.replace("\r\n", "\n").split("\n")
        # first segment may be junk after a header value context
        for line in parts[1:]:
            if ":" in line:
                name, _, val = line.partition(":")
                name = name.strip()
                if name and all(c.isalnum() or c in "-_" for c in name):
                    extra[name] = val.strip()[:120]
        if "x-vantacrawl-proof" not in {k.lower() for k in extra}:
            # also accept payload that is only the injected header name/value
            for line in parts:
                if ":" in line and "vantacrawl" in line.lower():
                    name, _, val = line.partition(":")
                    extra[name.strip()] = val.strip()[:120]
    body = page("CRLF", f"<p>echo={html.escape(q[:200])}</p>")
    send(handler, 200, body, headers=extra or None, head_only=head_only)


@register(
    "/redirect",
    title="Open redirect",
    family="redirect",
    expected="open_redirect on next — never SSRF",
    tags=["active", "safe", "fp-guard"],
)
def open_redirect(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    nxt = params.get("next") or params.get("url") or params.get("return") or "/"
    # Also allow CRLF into Location for dual-signal testing
    headers = {"Location": nxt[:500]}
    body = page("Redirecting", f"<p>Redirect to <code>{html.escape(nxt[:200])}</code></p>")
    send(handler, 302, body, headers=headers, head_only=head_only)


@register(
    "/redirect/safe",
    title="Safe same-origin redirect",
    family="redirect",
    expected="no open_redirect confirmation",
    tags=["control"],
)
def redirect_safe(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    nxt = params.get("next", "/")
    parsed = urlparse(nxt)
    if parsed.scheme or parsed.netloc:
        # force relative
        nxt = "/"
    send(handler, 302, page("Safe redirect", "<p>ok</p>"), headers={"Location": nxt}, head_only=head_only)

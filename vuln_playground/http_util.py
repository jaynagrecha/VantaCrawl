"""Shared HTTP helpers for the vuln playground (stdlib only)."""

from __future__ import annotations

import html
import json
import urllib.parse
from http.server import BaseHTTPRequestHandler
from typing import Any, Dict, Optional


def read_body(handler: BaseHTTPRequestHandler) -> bytes:
    length = int(handler.headers.get("Content-Length") or 0)
    if length <= 0:
        return b""
    return handler.rfile.read(length)


def parse_params(handler: BaseHTTPRequestHandler) -> Dict[str, str]:
    parsed = urllib.parse.urlparse(handler.path)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    out: Dict[str, str] = {k: (v[0] if v else "") for k, v in qs.items()}
    if handler.command == "POST":
        raw = read_body(handler).decode("utf-8", errors="replace")
        ctype = (handler.headers.get("Content-Type") or "").lower()
        if "application/json" in ctype:
            try:
                data = json.loads(raw or "{}")
                if isinstance(data, dict):
                    for k, v in data.items():
                        out[str(k)] = "" if v is None else str(v)
            except Exception:
                pass
        else:
            form = urllib.parse.parse_qs(raw, keep_blank_values=True)
            for k, v in form.items():
                out[k] = v[0] if v else ""
    return out


def send(
    handler: BaseHTTPRequestHandler,
    status: int,
    body: bytes,
    headers: Optional[Dict[str, str]] = None,
    *,
    head_only: bool = False,
) -> None:
    handler.send_response(status)
    hdrs = {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"}
    if headers:
        hdrs.update(headers)
    for k, v in hdrs.items():
        handler.send_header(k, v)
    payload = b"" if head_only else body
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    if payload:
        handler.wfile.write(payload)


def page(title: str, body: str, *, extra_head: str = "") -> bytes:
    return (
        "<!DOCTYPE html><html><head>"
        f"<meta charset='utf-8'><title>{html.escape(title)}</title>{extra_head}"
        "<style>"
        "body{font-family:ui-sans-serif,system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;line-height:1.45}"
        "code,pre{background:#f4f4f5;padding:.15rem .35rem;border-radius:4px}"
        "pre{padding:.75rem;overflow:auto}"
        "a{color:#0b57d0}"
        ".tag{display:inline-block;font-size:.75rem;background:#fee2e2;color:#991b1b;"
        "padding:.1rem .4rem;border-radius:4px;margin-right:.35rem}"
        ".ok{background:#dcfce7;color:#166534}"
        ".warn{background:#fef3c7;color:#92400e}"
        "</style></head><body>"
        f"<h1>{html.escape(title)}</h1>{body}</body></html>"
    ).encode("utf-8")


def json_bytes(data: Any) -> bytes:
    return json.dumps(data, indent=2, default=str).encode("utf-8")

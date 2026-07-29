"""Generic evidence helpers (no Horizon hardcodes)."""

from __future__ import annotations

import hashlib
import re
import secrets
from typing import Any, Dict, Optional, Tuple


def new_nonce(nbytes: int = 8) -> str:
    return secrets.token_hex(nbytes)


def new_probe_id(prefix: str = "vp") -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def body_hash(body: str) -> str:
    norm = re.sub(r"\s+", " ", (body or "")[:50000]).strip()
    return hashlib.sha256(norm.encode("utf-8", errors="replace")).hexdigest()[:16]


def response_snap(resp: Any) -> Dict[str, Any]:
    status = int(getattr(resp, "status_code", 0) or 0)
    try:
        body = resp.text or ""
    except Exception:
        body = ""
    headers = {}
    try:
        headers = {str(k).lower(): str(v) for k, v in dict(getattr(resp, "headers", {}) or {}).items()}
    except Exception:
        headers = {}
    return {
        "status": status,
        "body": body,
        "headers": headers,
        "body_hash": body_hash(body),
        "final_url": str(getattr(resp, "url", "") or ""),
    }


def looks_reflected(body: str, token: str) -> bool:
    if not token:
        return False
    return token in (body or "")


def arithmetic_proof_present(body: str, expected: str, payload: str) -> bool:
    """True when expected result appears independently of raw payload echo."""
    if not expected or expected not in (body or ""):
        return False
    if payload and expected in payload:
        return False
    return True


def with_query_param(url: str, name: str, value: str) -> str:
    from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

    parsed = urlparse(url)
    pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k != name]
    pairs.append((name, value))
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(pairs), parsed.fragment)
    )


async def http_send(client: Any, method: str, url: str, *, data: Optional[Dict[str, str]] = None) -> Any:
    method_u = (method or "GET").upper()
    if method_u == "POST":
        return await client.post(url, data=data or {})
    return await client.get(url)

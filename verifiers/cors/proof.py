"""HMAC-bound CORS proof tokens and proof-page URL minting."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote, urljoin

from verifiers.cors.url_safety import origin_of, validate_proof_target

TOKEN_VERSION = 1
DEFAULT_TTL_SEC = 600


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def mint_proof_token(
    *,
    secret: str,
    scan_id: str,
    candidate_id: str,
    probe_id: str,
    nonce: str,
    target_url: str,
    target_origin: str,
    credential_mode: str,
    canary: str,
    method: str = "GET",
    ttl_sec: int = DEFAULT_TTL_SEC,
    now: Optional[float] = None,
) -> str:
    if not secret:
        raise ValueError("cors_proof_secret_required")
    ok, reason = validate_proof_target(target_url, expected_origin=target_origin)
    if not ok:
        raise ValueError(f"unsafe_target:{reason}")
    cm = "include" if credential_mode == "include" else "omit"
    ts = int(now if now is not None else time.time())
    payload: Dict[str, Any] = {
        "v": TOKEN_VERSION,
        "sid": scan_id,
        "cid": candidate_id,
        "pid": probe_id,
        "n": nonce,
        "tu": target_url,
        "to": target_origin or origin_of(target_url),
        "cm": cm,
        "canary": canary or "",
        "method": (method or "GET").upper(),
        "exp": ts + int(ttl_sec),
        "iat": ts,
    }
    body = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    sig = _b64e(hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest())
    return f"{body}.{sig}"


def verify_proof_token(
    token: str,
    *,
    secret: str,
    now: Optional[float] = None,
    resolve_dns: bool = False,
) -> Tuple[Optional[Dict[str, Any]], str]:
    if not secret or not token or "." not in token:
        return None, "malformed"
    body, _, sig = token.partition(".")
    if not body or not sig:
        return None, "malformed"
    expect = _b64e(hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(expect, sig):
        return None, "bad_signature"
    try:
        payload = json.loads(_b64d(body).decode("utf-8"))
    except Exception:
        return None, "bad_payload"
    if int(payload.get("v") or 0) != TOKEN_VERSION:
        return None, "bad_version"
    ts = int(now if now is not None else time.time())
    if int(payload.get("exp") or 0) < ts:
        return None, "expired"
    tu = str(payload.get("tu") or "")
    to = str(payload.get("to") or "")
    ok, reason = validate_proof_target(tu, expected_origin=to, resolve_dns=resolve_dns)
    if not ok:
        return None, reason
    if str(payload.get("method") or "GET").upper() not in ("GET", "HEAD"):
        return None, "method_not_allowed"
    return payload, "ok"


def proof_page_url(proof_origin_base: str, token: str) -> str:
    base = (proof_origin_base or "").rstrip("/") + "/"
    return urljoin(base, f"api/cors-proof/run?t={quote(token, safe='')}")


def proof_origin_configured(proof_origin_base: str) -> bool:
    return bool((proof_origin_base or "").strip())

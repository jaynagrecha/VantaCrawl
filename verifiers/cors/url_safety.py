"""SSRF-safe destination checks for CORS proof tokens (no arbitrary proxying)."""

from __future__ import annotations

import ipaddress
import socket
from typing import Optional, Tuple
from urllib.parse import urlparse


_BLOCKED_HOST_SUFFIXES = (
    ".local",
    ".internal",
    ".localhost",
)
_BLOCKED_HOSTS = frozenset(
    {
        "localhost",
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
    }
)


def _host_blocked(host: str) -> bool:
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return True
    if h in _BLOCKED_HOSTS:
        return True
    if any(h.endswith(suf) for suf in _BLOCKED_HOST_SUFFIXES):
        return True
    if h == "0.0.0.0":
        return True
    try:
        ip = ipaddress.ip_address(h)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return True
        # AWS/GCP metadata
        if str(ip) in ("169.254.169.254", "169.254.170.2"):
            return True
    except ValueError:
        pass
    return False


def resolve_blocked(host: str) -> bool:
    """Best-effort DNS resolution block for private answers."""
    if _host_blocked(host):
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or str(ip) in ("169.254.169.254", "169.254.170.2")
            ):
                return True
        except ValueError:
            continue
    return False


def validate_proof_target(
    target_url: str,
    *,
    expected_origin: str,
    resolve_dns: bool = False,
) -> Tuple[bool, str]:
    """Return (ok, reason). Only http(s) to the exact authorized origin."""
    try:
        parsed = urlparse(target_url)
    except Exception:
        return False, "invalid_url"
    if parsed.scheme not in ("http", "https"):
        return False, "scheme_not_allowed"
    if not parsed.netloc:
        return False, "missing_host"
    if parsed.username or parsed.password:
        return False, "userinfo_not_allowed"
    host = parsed.hostname or ""
    if _host_blocked(host):
        return False, "host_blocked"
    if resolve_dns and resolve_blocked(host):
        return False, "resolved_private"
    try:
        exp = urlparse(expected_origin)
    except Exception:
        return False, "invalid_expected_origin"
    if not exp.scheme or not exp.netloc:
        return False, "invalid_expected_origin"
    actual_origin = f"{parsed.scheme}://{parsed.netloc}".lower()
    expect_origin = f"{exp.scheme}://{exp.netloc}".lower()
    if actual_origin != expect_origin:
        return False, "origin_mismatch"
    return True, "ok"


def origin_of(url: str) -> str:
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        return ""
    return f"{p.scheme}://{p.netloc}"

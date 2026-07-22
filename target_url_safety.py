"""Reject scan targets that resolve to private / metadata networks (SSRF guard)."""

from __future__ import annotations

import ipaddress
import socket
from typing import Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "kubernetes.default",
        "kubernetes.default.svc",
    }
)

# Cloud instance metadata (link-local)
_METADATA_IPS = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
)


def _ip_is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip in _METADATA_IPS:
        return True
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _host_label_blocked(host: str) -> bool:
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return True
    if h in _BLOCKED_HOSTNAMES:
        return True
    if h.endswith(".localhost") or h.endswith(".local") or h.endswith(".internal"):
        return True
    return False


def _resolve_ips(host: str) -> List[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    ips: List[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        literal = ipaddress.ip_address(host)
        return [literal]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve host '{host}': {exc}") from exc
    for info in infos:
        addr = info[4][0]
        try:
            ips.append(ipaddress.ip_address(addr))
        except ValueError:
            continue
    if not ips:
        raise ValueError(f"No IP addresses resolved for host '{host}'")
    return ips


def validate_public_http_url(url: str) -> str:
    """Return normalized URL or raise ValueError if unsafe / invalid."""
    text = (url or "").strip()
    if not text.startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")
    parsed = urlparse(text)
    host = parsed.hostname
    if not host:
        raise ValueError("URL is missing a hostname")
    if parsed.username or parsed.password:
        raise ValueError("URLs with embedded credentials are not allowed")
    if _host_label_blocked(host):
        raise ValueError(f"Host '{host}' is not allowed (private/local name)")
    for ip in _resolve_ips(host):
        if _ip_is_blocked(ip):
            raise ValueError(
                f"Host '{host}' resolves to blocked address {ip} "
                "(private, loopback, link-local, or metadata)"
            )
    return text


def validate_public_http_urls(urls: Iterable[str]) -> List[str]:
    out: List[str] = []
    for raw in urls:
        item = (raw or "").strip()
        if not item:
            continue
        out.append(validate_public_http_url(item))
    return out

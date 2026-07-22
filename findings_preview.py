"""Build live Findings preview rows (masked evidence + revealable full value)."""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

_COOKIE_NAME_RE = re.compile(r"(?i)cookie\s+`([^`]+)`")
_IMPACT_IN_DETAIL_RE = re.compile(r"(?i)\bImpact:\s*([a-z_]+)")
_MASK_MARK_RE = re.compile(r"(?:…|\.\.\.)")


def _host_key(url: str) -> str:
    try:
        host = (urlparse(url).netloc or "").lower()
    except Exception:
        host = (url or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def _cookie_name(detail: str) -> str:
    match = _COOKIE_NAME_RE.search(detail or "")
    return (match.group(1) or "").strip().lower() if match else ""


def _impact_of(item: Dict[str, Any], detail: str) -> str:
    impact = str(item.get("impact") or "").strip()
    if impact:
        return impact
    match = _IMPACT_IN_DETAIL_RE.search(detail or "")
    return (match.group(1) or "").strip().lower() if match else ""


def _looks_masked(value: str) -> bool:
    return bool(_MASK_MARK_RE.search(value or "")) or "***" in (value or "")


def build_findings_preview(findings: Optional[Iterable[Any]], *, limit: int = 80) -> List[Dict[str, str]]:
    """Collapse cookie clones and mask credential evidence for the live cockpit."""
    out: List[Dict[str, str]] = []
    seen_cookies: set = set()
    try:
        from security_scan import mask_secret_value
    except Exception:
        return []

    for item in list(findings or [])[: max(limit * 3, limit)]:
        if not isinstance(item, dict):
            continue
        if len(out) >= limit:
            break
        evidence = str(item.get("evidence") or "")
        detail = str(item.get("detail") or item.get("title") or "")
        category = str(item.get("category") or "")
        impact = _impact_of(item, detail)
        url = str(item.get("url") or "")
        cookie = _cookie_name(detail)
        if category == "authentication" and cookie:
            key = f"{_host_key(url)}|{cookie}"
            if key in seen_cookies:
                continue
            seen_cookies.add(key)

        secret_type = ""
        if category == "secrets_exposure":
            if detail.lower().startswith("exposed "):
                secret_type = detail[8:].split(" in response", 1)[0].strip()
            elif ":" in detail:
                secret_type = detail.split(":", 1)[0].strip()
        title = detail[:160]
        if secret_type and secret_type.lower() not in title.lower():
            title = f"{secret_type}: {title}"[:160]

        credentialish = category == "secrets_exposure" or impact in (
            "possible_credential",
            "stealable_credential",
        ) or bool(cookie)
        if credentialish and evidence and not _looks_masked(evidence):
            evidence_masked = mask_secret_value(evidence)
            evidence_full = evidence
        elif credentialish and evidence and _looks_masked(evidence):
            # Already masked at source — nothing left to reveal
            evidence_masked = evidence
            evidence_full = ""
        else:
            evidence_masked = evidence
            evidence_full = evidence

        out.append(
            {
                "severity": str(item.get("severity") or item.get("severity_label") or ""),
                "title": title,
                "url": url,
                "category": category,
                "secret_type": secret_type,
                "impact": impact,
                "validation": str(item.get("validation") or ""),
                "impact_summary": str(item.get("impact_summary") or ""),
                "role": str(item.get("role") or ""),
                "evidence_masked": evidence_masked,
                "evidence_full": evidence_full,
            }
        )
    return out

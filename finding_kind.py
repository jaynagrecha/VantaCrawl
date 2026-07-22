"""Separate demonstrated vulnerabilities from hardening / misconfiguration noise.

Security Misconfiguration ≠ Security Vulnerability. Header gaps and restricted
browser keys are hardening observations unless exploitability is proven.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set
from urllib.parse import urlparse

# Categories that are demonstrated attack classes when they fire with impact
_VULN_CATEGORIES = frozenset(
    {
        "xss",
        "sql_injection",
        "rce",
        "ssrf",
        "directory_traversal",
        "open_redirect",
        "csrf",
        "idor",
        "authentication",
        "http_methods",
        "cors",
        "api_leak",
        "file_upload",
        "mixed_content",
        "sensitive_path",
        "oauth",
        "jwt",
        "graphql",
        "mass_assignment",
        "rate_limit",
        "business_logic",
        "cloud",
        "websocket",
    }
)

# Recon / intel categories — hardening unless severity proves abuse
_INTEL_CATEGORIES = frozenset({"js_intel"})

_HARDENING_CATEGORIES = frozenset({"header_audit"})

_HARDENING_ROLES = frozenset({"hardening", "hygiene", "client_public_key"})


def _host(url: str) -> str:
    try:
        return (urlparse(url or "").netloc or "").lower()
    except Exception:
        return ""


def classify_finding_kind(
    *,
    category: str = "",
    role: str = "",
    impact: str = "",
    severity: str = "",
    detail: str = "",
) -> str:
    """Return ``vulnerability`` or ``hardening``."""
    cat = (category or "").lower().strip()
    role_l = (role or "").lower().strip()
    impact_l = (impact or "").lower().strip()
    detail_l = (detail or "").lower()

    abuse_proven = (
        "live abuse" in detail_l
        or ("storage" in detail_l and "listable" in detail_l)
        or "project config readable" in detail_l
        or ("places api" in detail_l and "unrestricted" in detail_l)
    )

    # Client key with proven abuse is a vulnerability even if role says client_public_key
    if cat == "secrets_exposure" and abuse_proven and severity in ("critical", "high", "medium"):
        return "vulnerability"

    if cat in _HARDENING_CATEGORIES or (
        role_l in _HARDENING_ROLES and not (cat == "secrets_exposure" and abuse_proven)
    ):
        if role_l == "client_public_key" and abuse_proven and severity in ("high", "medium"):
            return "vulnerability"
        return "hardening"

    # Client Google/Firebase keys stay hardening unless live abuse was proven
    if cat == "secrets_exposure":
        if impact_l in ("stealable_credential", "confirmed") and severity in (
            "critical",
            "high",
            "medium",
        ):
            return "vulnerability"
        if role_l == "client_public_key" or impact_l in (
            "limited_impact",
            "informational",
            "no_impact",
        ):
            return "hardening"
        if "firebase" in detail_l or "google" in detail_l or "aiza" in detail_l:
            if severity in ("info", "low"):
                return "hardening"
        if severity in ("critical", "high"):
            return "vulnerability"
        if severity == "medium" and impact_l in ("possible_credential", "stealable_credential"):
            return "vulnerability"
        return "hardening"

    if cat == "csrf":
        if severity in ("info", "low") or "hardening" in detail_l or role_l == "hardening":
            return "hardening"
        return "vulnerability"

    if cat == "idor" and severity in ("info",) and "candidate" in detail_l:
        return "hardening"

    if cat in _INTEL_CATEGORIES:
        return "hardening" if severity in ("info", "low") else "vulnerability"

    # Info-only SSO/JWT/biz-logic hints are hardening until verified/exploitable
    if cat in ("oauth", "jwt", "business_logic", "rate_limit", "websocket", "graphql", "mass_assignment", "cloud"):
        if severity == "info":
            return "hardening"
        if severity == "low" and (
            "missing aud" in detail_l
            or "candidate" in detail_l
            or "referenced" in detail_l
        ):
            return "hardening"

    if cat in _VULN_CATEGORIES:
        return "vulnerability"

    if "missing " in detail_l and any(
        x in detail_l for x in ("hsts", "csp", "x-frame", "referrer", "permissions-policy")
    ):
        return "hardening"

    return "vulnerability" if severity in ("critical", "high", "medium") else "hardening"


def apply_hardening_context(groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Rescore header hardening using co-observed attack findings on the same host."""
    xss_hosts: Set[str] = set()
    for g in groups:
        cat = str(g.get("category") or "").lower()
        detail = str(g.get("detail") or "").lower()
        if cat == "xss" or "xss" in detail or "cross-site scripting" in detail:
            for h in g.get("hosts") or []:
                xss_hosts.add(str(h).lower())
            for u in g.get("urls") or []:
                host = _host(u)
                if host:
                    xss_hosts.add(host)

    for g in groups:
        cat = str(g.get("category") or "").lower()
        detail = str(g.get("detail") or "").lower()
        role = str(g.get("role") or "")
        impact = str(g.get("impact") or "")
        severity = str(g.get("severity") or "info")

        hosts = {str(h).lower() for h in (g.get("hosts") or [])}
        for u in g.get("urls") or []:
            host = _host(u)
            if host:
                hosts.add(host)

        if cat == "header_audit" or "missing " in detail:
            if "csp" in detail or "content-security" in detail:
                if hosts & xss_hosts:
                    g["severity"] = "medium"
                    note = "Elevated: XSS also observed on this host — CSP would limit impact."
                    if note.lower() not in str(g.get("detail") or "").lower():
                        g["detail"] = f"{g.get('detail') or ''} [{note}]".strip()
                    g["impact_summary"] = (
                        "Missing CSP combined with observed XSS — defense-in-depth gap with attack path."
                    )
                else:
                    g["severity"] = "info"
                    g["role"] = g.get("role") or "hardening"
                    g["impact"] = g.get("impact") or "informational"
                    g["impact_summary"] = (
                        g.get("impact_summary")
                        or "Missing CSP without demonstrated XSS — hardening observation only."
                    )
            elif "hsts" in detail or "strict-transport" in detail:
                g["severity"] = "info"
                g["role"] = g.get("role") or "hardening"
                g["impact"] = g.get("impact") or "informational"
                g["impact_summary"] = (
                    g.get("impact_summary")
                    or "Missing HSTS on an HTTPS site — usually informational unless HTTP downgrade is proven."
                )
            elif "x-frame" in detail or "clickjacking" in detail:
                g["severity"] = "info"
                g["role"] = g.get("role") or "hardening"
                g["impact"] = g.get("impact") or "informational"
                g["impact_summary"] = (
                    g.get("impact_summary")
                    or "Missing X-Frame-Options without a clickjacking PoC — hardening observation only."
                )

        g["finding_kind"] = classify_finding_kind(
            category=cat,
            role=str(g.get("role") or role),
            impact=str(g.get("impact") or impact),
            severity=str(g.get("severity") or severity),
            detail=str(g.get("detail") or detail),
        )

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    groups.sort(
        key=lambda g: (
            0 if g.get("finding_kind") == "vulnerability" else 1,
            order.get(str(g.get("severity") or "info"), 5),
            -int(g.get("count") or 0),
            str(g.get("title") or ""),
        )
    )
    return groups

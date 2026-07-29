"""Horizon Catalog formal acceptance-benchmark route manifest.

Horizon is a deliberately vulnerable ground-truth corpus. This module defines
machine-readable expectations for scanner acceptance — not a recon target list.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

# Bucket classifications
BUCKET_SUPPORTED = "supported_required"
BUCKET_PASSIVE = "passive_manual"
BUCKET_UNSUPPORTED = "unsupported"

# Probe families VantaCrawl actively supports today (routing + kit).
SUPPORTED_ACTIVE_FAMILIES = frozenset(
    {
        "sqli",
        "rce",
        "command_injection",
        "ssti",
        "ssrf",
        "crlf",
        "traversal",
        "xss",
        "redirect",
        "csrf",
        "cors",
        "sensitive_path",
        "graphql",
        "header_audit",
        "robots_bypass",
    }
)

# Catalog families that are passive/manual unless dedicated logic already exists.
PASSIVE_MANUAL_FAMILIES = frozenset(
    {
        "race",
        "idor",
        "business_logic",
        "jwt",
        "smuggle",
        "deserialization",
        "ldap",
        "xpath",
        "nosql",
        "prototype_pollution",
        "websocket",
        "mass_assignment",
        "access_control",
        "oauth",
        "session",
        "auth",
        "otp",
        "saml",
        "spel",
        "ognl",
        "xxe",
        "ssi",
        "el",
        "cache",
        "hpp",
        "clickjack",
        "csp",
        "email",
        "tabnabbing",
        "sri",
        "client_storage",
        "log4j",
        "redos",
        "csv",
        "type_juggling",
        "zip_slip",
        "rfi",
        "firebase",
        "crypto",
        "k8s",
        "redis",
        "elasticsearch",
        "xmlrpc",
        "method_override",
        "put_upload",
        "jsonp",
        "host_header",
        "graphql_extra",
    }
)


def _entry(
    *,
    path: str,
    method: str = "GET",
    parameter: str,
    family: str,
    classification: str,
    bucket: str,
    modes: List[str],
    expected_result_state: str,
    expected_severity: str = "info",
    expected_validation: str = "unverified",
    must_not_confirm: bool = False,
    mandatory: bool = False,
    linked: bool = True,
    notes: str = "",
    probe_family: str = "",
) -> Dict[str, Any]:
    return {
        "path": path,
        "method": method.upper(),
        "parameter": parameter,
        "family": family,
        "probe_family": probe_family or family,
        "classification": classification,  # vulnerable | control
        "bucket": bucket,
        "modes": list(modes),
        "expected_result_state": expected_result_state,
        "expected_severity": expected_severity,
        "expected_validation": expected_validation,
        "must_not_confirm": bool(must_not_confirm),
        "mandatory": bool(mandatory),
        "linked": bool(linked),
        "notes": notes,
    }


def supported_mandatory_fixtures() -> List[Dict[str, Any]]:
    """Minimum supported fixtures required for Horizon acceptance."""
    safe_ext_lab = ["safe", "extended", "lab"]
    extended_lab = ["extended", "lab"]
    lab_only = ["lab"]
    return [
        # --- SQLi ---
        _entry(
            path="/sqli/error",
            parameter="id",
            family="sqli",
            classification="vulnerable",
            bucket=BUCKET_SUPPORTED,
            modes=safe_ext_lab,
            expected_result_state="differential_signal",
            expected_severity="high",
            expected_validation="unverified",
            mandatory=True,
            notes="Error-based SQLi — MySQL-style syntax differential.",
        ),
        _entry(
            path="/sqli/blind",
            parameter="id",
            family="sqli",
            classification="vulnerable",
            bucket=BUCKET_SUPPORTED,
            modes=extended_lab,
            expected_result_state="differential_signal",
            expected_severity="high",
            expected_validation="unverified",
            mandatory=True,
            notes="Boolean blind differential (extended+).",
        ),
        _entry(
            path="/sqli/safe",
            parameter="id",
            family="sqli",
            classification="control",
            bucket=BUCKET_SUPPORTED,
            modes=safe_ext_lab,
            expected_result_state="negative",
            expected_severity="info",
            expected_validation="unverified",
            must_not_confirm=True,
            mandatory=True,
            notes="Negative control — identical body for all payloads.",
        ),
        # --- RCE / CMDI ---
        _entry(
            path="/rce/arith",
            parameter="cmd",
            family="rce",
            classification="vulnerable",
            bucket=BUCKET_SUPPORTED,
            modes=safe_ext_lab,
            expected_result_state="execution_confirmed",
            expected_severity="critical",
            expected_validation="confirmed",
            mandatory=True,
            notes="Arithmetic / marker echo RCE sink.",
        ),
        _entry(
            path="/rce/reflect",
            parameter="cmd",
            family="rce",
            classification="control",
            bucket=BUCKET_SUPPORTED,
            modes=safe_ext_lab,
            expected_result_state="negative",
            expected_severity="info",
            expected_validation="unverified",
            must_not_confirm=True,
            mandatory=True,
            notes="Reflection-only — must never confirm RCE.",
        ),
        _entry(
            path="/cmdi/ping",
            parameter="host",
            family="command_injection",
            probe_family="rce",
            classification="vulnerable",
            bucket=BUCKET_SUPPORTED,
            modes=safe_ext_lab,
            expected_result_state="execution_confirmed",
            expected_severity="critical",
            expected_validation="confirmed",
            mandatory=True,
            notes="OS command injection via host metacharacters.",
        ),
        # --- SSTI ---
        _entry(
            path="/ssti/eval",
            parameter="name",
            family="ssti",
            classification="vulnerable",
            bucket=BUCKET_SUPPORTED,
            modes=safe_ext_lab,
            expected_result_state="execution_confirmed",
            expected_severity="high",
            expected_validation="confirmed",
            mandatory=True,
        ),
        _entry(
            path="/ssti/reflect",
            parameter="name",
            family="ssti",
            classification="control",
            bucket=BUCKET_SUPPORTED,
            modes=safe_ext_lab,
            expected_result_state="negative",
            expected_severity="info",
            expected_validation="unverified",
            must_not_confirm=True,
            mandatory=True,
        ),
        # --- SSRF ---
        _entry(
            path="/ssrf/fetch",
            parameter="url",
            family="ssrf",
            classification="vulnerable",
            bucket=BUCKET_SUPPORTED,
            modes=safe_ext_lab,
            expected_result_state="inconclusive",
            expected_severity="info",
            expected_validation="unverified",
            mandatory=True,
            notes=(
                "Probe must be sent. OOB confirmation only when callback receiver configured; "
                "without OOB, result_state may be inconclusive/reflected_only — never silent skip."
            ),
        ),
        _entry(
            path="/ssrf/reflect",
            parameter="url",
            family="ssrf",
            classification="control",
            bucket=BUCKET_SUPPORTED,
            modes=safe_ext_lab,
            expected_result_state="reflected_only",
            expected_severity="info",
            expected_validation="unverified",
            must_not_confirm=True,
            mandatory=True,
            notes="Must not confirm SSRF via OOB.",
        ),
        # --- CRLF ---
        _entry(
            path="/crlf",
            parameter="q",
            family="crlf",
            classification="vulnerable",
            bucket=BUCKET_SUPPORTED,
            modes=safe_ext_lab,
            expected_result_state="execution_confirmed",
            expected_severity="high",
            expected_validation="confirmed",
            mandatory=True,
        ),
        # --- Traversal ---
        _entry(
            path="/trav/download",
            parameter="path",
            family="traversal",
            classification="vulnerable",
            bucket=BUCKET_SUPPORTED,
            modes=safe_ext_lab,
            expected_result_state="differential_signal",
            expected_severity="medium",
            expected_validation="unverified",
            mandatory=True,
            notes="Safe/extended: differential; lab+canary may confirm.",
        ),
        _entry(
            path="/trav/view",
            parameter="file",
            family="traversal",
            classification="vulnerable",
            bucket=BUCKET_SUPPORTED,
            modes=lab_only,
            expected_result_state="canary_file_confirmed",
            expected_severity="high",
            expected_validation="confirmed",
            mandatory=True,
            notes="Lab canary confirmation when fixture configured.",
        ),
        # --- XSS ---
        _entry(
            path="/xss/reflected",
            parameter="q",
            family="xss",
            classification="vulnerable",
            bucket=BUCKET_SUPPORTED,
            modes=safe_ext_lab,
            expected_result_state="reflected_only",
            expected_severity="info",
            expected_validation="unverified",
            mandatory=True,
        ),
        _entry(
            path="/xss/encoded",
            parameter="q",
            family="xss",
            classification="control",
            bucket=BUCKET_SUPPORTED,
            modes=safe_ext_lab,
            expected_result_state="negative",
            expected_severity="info",
            expected_validation="unverified",
            must_not_confirm=True,
            mandatory=True,
        ),
        _entry(
            path="/xss/browser",
            parameter="q",
            family="xss",
            classification="vulnerable",
            bucket=BUCKET_SUPPORTED,
            modes=lab_only,
            expected_result_state="browser_execution_confirmed",
            expected_severity="high",
            expected_validation="confirmed",
            mandatory=True,
            notes="Requires browser confirmation capability in lab mode.",
        ),
        # --- Redirect ---
        _entry(
            path="/redirect",
            parameter="next",
            family="redirect",
            classification="vulnerable",
            bucket=BUCKET_SUPPORTED,
            modes=safe_ext_lab,
            expected_result_state="execution_confirmed",
            expected_severity="high",
            expected_validation="confirmed",
            mandatory=True,
            notes="Open redirect — never classified as SSRF.",
        ),
        _entry(
            path="/redirect/safe",
            parameter="next",
            family="redirect",
            classification="control",
            bucket=BUCKET_SUPPORTED,
            modes=safe_ext_lab,
            expected_result_state="negative",
            expected_severity="info",
            expected_validation="unverified",
            must_not_confirm=True,
            mandatory=True,
            notes="Same-origin redirect control — must not confirm open redirect.",
        ),
    ]


def classify_catalog_route(item: Dict[str, Any]) -> str:
    """Map a live /catalog.json entry into a bucket."""
    family = str(item.get("family") or "").lower()
    tags = {str(t).lower() for t in (item.get("tags") or [])}
    path = str(item.get("path") or "")
    # Mandatory supported overrides
    for fix in supported_mandatory_fixtures():
        if fix["path"] == path:
            return fix["bucket"]
    if "control" in tags or "fp-guard" in tags:
        # Controls for supported families stay supported
        if family in SUPPORTED_ACTIVE_FAMILIES or family in {
            "command_injection",
            "lfi",
            "header_injection",
        }:
            return BUCKET_SUPPORTED
    if family in SUPPORTED_ACTIVE_FAMILIES or family in {
        "command_injection",
        "lfi",
        "header_injection",
        "open_redirect",
    }:
        if "active" in tags or "safe" in tags or "extended" in tags or "lab" in tags or "oob" in tags:
            return BUCKET_SUPPORTED
        if "passive" in tags or "enum" in tags:
            return BUCKET_PASSIVE
        return BUCKET_SUPPORTED
    if family in PASSIVE_MANUAL_FAMILIES or "passive" in tags:
        return BUCKET_PASSIVE
    if family in ("discovery", "robots_bypass", "listing", "backup", "git", "actuator", "info_leak", "api"):
        return BUCKET_PASSIVE
    return BUCKET_UNSUPPORTED


def build_manifest(catalog: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Build the formal Horizon acceptance manifest.

    Merges mandatory supported fixtures with the live/local catalog for
    passive/unsupported inventory completeness.
    """
    catalog = list(catalog or [])
    by_path = {str(c.get("path") or ""): c for c in catalog}

    routes: List[Dict[str, Any]] = []
    seen = set()

    for fix in supported_mandatory_fixtures():
        cat = by_path.get(fix["path"]) or {}
        row = dict(fix)
        row["title"] = cat.get("title") or fix["path"]
        row["catalog_expected"] = cat.get("expected") or ""
        row["catalog_tags"] = list(cat.get("tags") or [])
        routes.append(row)
        seen.add(fix["path"])

    for item in catalog:
        path = str(item.get("path") or "")
        if not path or path in seen:
            continue
        bucket = classify_catalog_route(item)
        family = str(item.get("family") or "unknown")
        tags = {str(t).lower() for t in (item.get("tags") or [])}
        classification = "control" if ("control" in tags or "fp-guard" in tags) else "vulnerable"
        # Parameter unknown for inventory-only rows — runner marks no_parameter if needed.
        routes.append(
            {
                "path": path,
                "method": (item.get("methods") or ["GET"])[0],
                "parameter": "",
                "family": family,
                "probe_family": "rce" if family == "command_injection" else family,
                "classification": classification,
                "bucket": bucket,
                "modes": (
                    ["safe", "extended", "lab"]
                    if bucket == BUCKET_SUPPORTED
                    else (["passive"] if bucket == BUCKET_PASSIVE else [])
                ),
                "expected_result_state": (
                    "negative"
                    if classification == "control"
                    else ("fixture_discovered_no_compatible_detector" if bucket == BUCKET_UNSUPPORTED else "")
                ),
                "expected_severity": "info",
                "expected_validation": "unverified",
                "must_not_confirm": classification == "control",
                "mandatory": False,
                "linked": bool(item.get("linked", True)),
                "title": item.get("title") or path,
                "catalog_expected": item.get("expected") or "",
                "catalog_tags": list(item.get("tags") or []),
                "notes": (
                    "Fixture discovered but no compatible active detector exists."
                    if bucket == BUCKET_UNSUPPORTED
                    else (item.get("notes") or "")
                ),
            }
        )
        seen.add(path)

    return {
        "name": "Horizon Catalog Acceptance Benchmark",
        "version": "1",
        "target": "https://horizon-catalog.onrender.com/",
        "ground_truth": True,
        "buckets": {
            BUCKET_SUPPORTED: "Supported and must detect (or explicitly gap-report)",
            BUCKET_PASSIVE: "Passive/manual candidate only",
            BUCKET_UNSUPPORTED: "Explicitly unsupported — must not silently skip when discovered",
        },
        "routes": routes,
        "mandatory_supported_count": sum(1 for r in routes if r.get("mandatory")),
        "counts": {
            BUCKET_SUPPORTED: sum(1 for r in routes if r.get("bucket") == BUCKET_SUPPORTED),
            BUCKET_PASSIVE: sum(1 for r in routes if r.get("bucket") == BUCKET_PASSIVE),
            BUCKET_UNSUPPORTED: sum(1 for r in routes if r.get("bucket") == BUCKET_UNSUPPORTED),
        },
    }


def load_catalog_from_playground() -> List[Dict[str, Any]]:
    """Load catalog by importing local vuln_playground registry when available."""
    import sys

    root = Path(__file__).resolve().parents[1] / "vuln_playground"
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from registry import catalog, load_vuln_modules  # type: ignore

    load_vuln_modules()
    return catalog()


def default_manifest_path() -> Path:
    return Path(__file__).resolve().parent / "manifest.json"


def write_manifest(path: Optional[Path] = None, catalog: Optional[List[Dict[str, Any]]] = None) -> Path:
    out = path or default_manifest_path()
    if catalog is None:
        try:
            catalog = load_catalog_from_playground()
        except Exception:
            catalog = []
    data = build_manifest(catalog)
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return out


def load_manifest(path: Optional[Path] = None) -> Dict[str, Any]:
    p = path or default_manifest_path()
    if not p.exists():
        write_manifest(p)
    return json.loads(p.read_text(encoding="utf-8"))


def mandatory_for_mode(manifest: Dict[str, Any], mode: str) -> List[Dict[str, Any]]:
    mode_n = (mode or "safe").lower()
    return [
        r
        for r in manifest.get("routes") or []
        if r.get("mandatory")
        and r.get("bucket") == BUCKET_SUPPORTED
        and mode_n in (r.get("modes") or [])
    ]

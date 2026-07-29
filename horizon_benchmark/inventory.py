"""Horizon Catalog inventory and entire-catalog support classification.

Benchmark-only module — may read the local/live catalog. Production verifiers
must not import fixture paths from here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from horizon_benchmark.manifest import (
    BUCKET_PASSIVE,
    BUCKET_SUPPORTED,
    BUCKET_UNSUPPORTED,
    build_manifest,
    load_catalog_from_playground,
    load_manifest,
    write_manifest,
)
from verifiers.contract import PRODUCT_CLAIM
from verifiers.maturity import classify_support_from_maturity
from verifiers.registry import capability_registry, supported_families


PHASE1_FAMILIES = frozenset(
    {
        "sqli",
        "rce",
        "command_injection",
        "ssti",
        "xss",
        "ssrf",
        "redirect",
        "open_redirect",
        "traversal",
        "lfi",
        "crlf",
        "header_injection",
        "csrf",
        "dom_clobber",
    }
)


def build_fixture_inventory(catalog: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Full Horizon fixture inventory with support classification."""
    catalog = list(catalog or load_catalog_from_playground())
    manifest = build_manifest(catalog)
    caps = capability_registry()
    families = set(supported_families(phase=1))
    # Map probe families to capability ids
    fam_to_cap = {}
    for cid, meta in caps.items():
        fam_to_cap[str(meta.get("family"))] = cid

    rows = []
    for route in manifest.get("routes") or []:
        family = str(route.get("family") or "unknown").lower()
        probe_family = str(route.get("probe_family") or family).lower()
        bucket = str(route.get("bucket") or "")
        tags = {str(t).lower() for t in (route.get("catalog_tags") or route.get("tags") or [])}
        # DOM clobber tagged routes
        if "dom-clobber" in tags or "dom_clobber" in family:
            probe_family = "dom_clobber"
            family_for_cap = "dom_clobber"
        else:
            family_for_cap = probe_family if probe_family in fam_to_cap else family

        cap_id = fam_to_cap.get(family_for_cap) or fam_to_cap.get(
            {"command_injection": "rce", "lfi": "traversal", "open_redirect": "redirect", "header_injection": "crlf"}.get(
                family, family
            )
        )

        # Maturity-aware classification: registry/contract alone ≠ supported_active.
        fam_for_maturity = (
            "dom_clobber"
            if ("dom-clobber" in tags or "dom_clobber" in family or "dom-clobber" in str(route.get("path") or ""))
            else family_for_cap
        )
        matured = classify_support_from_maturity(
            bucket=bucket,
            family=fam_for_maturity,
            path=str(route.get("path") or ""),
            prior_cap_id=str(cap_id or ""),
        )
        support = matured["support_classification"]
        cap_id = matured.get("verifier_capability_id") or cap_id or ""
        missing = matured.get("classification_reason") or ""
        if support == "unsupported" and bucket == BUCKET_UNSUPPORTED:
            missing = f"no_verifier_for_family:{family}"

        rows.append(
            {
                "fixture_id": f"hz:{route.get('path')}",
                "path": route.get("path"),
                "method": route.get("method") or "GET",
                "family": family,
                "probe_family": (
                    "dom_clobber"
                    if (
                        "dom-clobber" in tags
                        or "dom_clobber" in family
                        or "dom-clobber" in str(route.get("path") or "")
                    )
                    else probe_family
                ),
                "classification": route.get("classification"),
                "bucket": bucket,
                "support_classification": support,
                "capability_maturity": matured.get("capability_maturity") or "",
                "verifier_capability_id": cap_id or "",
                "verifier_implementation_module": matured.get("verifier_implementation_module") or "",
                "implementation_status": matured.get("implementation_status") or "",
                "discovery_support": bool(matured.get("discovery_support")),
                "input_modelling_support": bool(matured.get("input_modelling_support")),
                "request_construction_support": bool(matured.get("request_construction_support")),
                "baseline_implementation": bool(matured.get("baseline_implementation")),
                "negative_control_implementation": bool(matured.get("negative_control_implementation")),
                "replay_implementation": bool(matured.get("replay_implementation")),
                "proof_contract": bool(matured.get("proof_contract")),
                "finding_emission_implementation": bool(matured.get("finding_emission_implementation")),
                "missing_capability": missing,
                "classification_reason": matured.get("classification_reason") or "",
                "missing_lifecycle_stages": list(matured.get("missing_lifecycle_stages") or []),
                "modes": list(route.get("modes") or []),
                "mandatory": bool(route.get("mandatory")),
                "must_not_confirm": bool(route.get("must_not_confirm")),
                "expected_result_state": route.get("expected_result_state") or "",
                "title": route.get("title") or "",
                "catalog_expected": route.get("catalog_expected") or "",
                "input_channels": _infer_channels(route),
            }
        )

    maturity_counts = {
        "contract_only": 0,
        "registered_adapter": 0,
        "executable_unvalidated": 0,
        "live_validated": 0,
    }
    for r in rows:
        m = r.get("capability_maturity") or ""
        if m in maturity_counts:
            maturity_counts[m] += 1

    summary = {
        "catalog_fixtures": len(rows),
        "supported_active": sum(1 for r in rows if r["support_classification"] == "supported_active"),
        "passive_manual": sum(1 for r in rows if r["support_classification"] == "passive_manual"),
        "unsupported": sum(1 for r in rows if r["support_classification"] == "unsupported"),
        "capability_maturity_counts": maturity_counts,
        "live_recall_denominator": sum(
            1 for r in rows if r.get("capability_maturity") == "live_validated"
        ),
        "phase1_capability_ids": sorted(caps.keys()),
        "product_claim": PRODUCT_CLAIM,
    }
    return {"summary": summary, "fixtures": rows, "capabilities": caps}


def _infer_channels(route: Dict[str, Any]) -> List[str]:
    channels = ["query"]
    method = str(route.get("method") or "GET").upper()
    if method == "POST":
        channels.append("form")
    tags = {str(t).lower() for t in (route.get("catalog_tags") or [])}
    if "browser" in tags:
        channels.append("browser")
    if "oob" in tags:
        channels.append("oob")
    return channels


def write_inventory(path: Optional[Path] = None) -> Path:
    path = path or Path("/opt/cursor/artifacts/verifier_phase1/fixture_inventory.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    data = build_fixture_inventory()
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def support_classification_lists(inventory: Optional[Dict[str, Any]] = None) -> Dict[str, List[str]]:
    inv = inventory or build_fixture_inventory()
    out = {"supported_active": [], "passive_manual": [], "unsupported": []}
    for row in inv.get("fixtures") or []:
        key = row.get("support_classification")
        if key in out:
            out[key].append(str(row.get("path")))
    return out

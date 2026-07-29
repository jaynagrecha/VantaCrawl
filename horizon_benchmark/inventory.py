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

        if bucket == BUCKET_UNSUPPORTED:
            support = "unsupported"
            missing = f"no_verifier_for_family:{family}"
        elif bucket == BUCKET_PASSIVE:
            support = "passive_manual"
            missing = "" if not cap_id else ""
            if family_for_cap not in families and family not in PHASE1_FAMILIES:
                missing = f"passive_or_manual:{family}"
        elif cap_id:
            support = "supported_active"
            missing = ""
        elif family in PHASE1_FAMILIES or probe_family in PHASE1_FAMILIES:
            support = "supported_active"
            missing = "capability_pending_wiring"
            cap_id = f"phase1_{probe_family}"
        else:
            support = "unsupported" if bucket != BUCKET_PASSIVE else "passive_manual"
            missing = f"no_phase1_verifier:{family}"

        rows.append(
            {
                "fixture_id": f"hz:{route.get('path')}",
                "path": route.get("path"),
                "method": route.get("method") or "GET",
                "family": family,
                "probe_family": probe_family,
                "classification": route.get("classification"),
                "bucket": bucket,
                "support_classification": support,
                "verifier_capability_id": cap_id or "",
                "missing_capability": missing,
                "modes": list(route.get("modes") or []),
                "mandatory": bool(route.get("mandatory")),
                "must_not_confirm": bool(route.get("must_not_confirm")),
                "expected_result_state": route.get("expected_result_state") or "",
                "title": route.get("title") or "",
                "catalog_expected": route.get("catalog_expected") or "",
                "input_channels": _infer_channels(route),
            }
        )

    summary = {
        "catalog_fixtures": len(rows),
        "supported_active": sum(1 for r in rows if r["support_classification"] == "supported_active"),
        "passive_manual": sum(1 for r in rows if r["support_classification"] == "passive_manual"),
        "unsupported": sum(1 for r in rows if r["support_classification"] == "unsupported"),
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

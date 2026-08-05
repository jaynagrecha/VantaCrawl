"""Production-neutral Phase-1 execution planner.

Capability-driven scheduling from discovered surfaces + verifier registry + mode
+ dependency availability. No Horizon routes, fixture IDs, or catalog assumptions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from verifiers.maturity import (
    MATURITY_EXECUTABLE_UNVALIDATED,
    MATURITY_LIVE_VALIDATED,
    assess_capability_maturity,
)
from verifiers.registry import get_verifier

ATTEMPTED = "attempted"
MODE_EXCLUDED = "mode_excluded"
DISCOVERY_MISSING = "discovery_missing"
NO_EXECUTABLE_ADAPTER = "no_executable_adapter"
DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
BREAKER_PAUSED = "breaker_paused"
TRANSPORT_FAILED = "transport_failed"
VERIFICATION_FAILED = "verification_failed"

EXECUTABLE_MATURITIES = frozenset(
    {MATURITY_EXECUTABLE_UNVALIDATED, MATURITY_LIVE_VALIDATED}
)

FAMILY_ALIASES = {
    "command_injection": "rce",
    "cmdi": "rce",
    "sql_injection": "sqli",
    "open_redirect": "redirect",
    "lfi": "traversal",
    "directory_traversal": "traversal",
    "header_injection": "crlf",
    "dom-clobber": "dom_clobber",
    "html_injection": "xss",
}


@dataclass
class DependencyAvailability:
    http_client: bool = True
    browser: bool = False
    oob_callback: bool = False
    traversal_canary: bool = False
    session: bool = False
    cors_proof_origin: bool = False


@dataclass
class CandidateSurface:
    """One discovered (or inventory-supplied) surface eligible for Phase-1 planning."""

    candidate_id: str
    url: str
    path: str
    method: str = "GET"
    family: str = ""
    probe_family: str = ""
    parameter: str = ""
    classification: str = "vulnerable"  # vulnerable | control | unknown
    must_not_confirm: bool = False
    modes: List[str] = field(default_factory=list)  # empty = all modes
    support_classification: str = "supported_active"
    capability_maturity: str = MATURITY_EXECUTABLE_UNVALIDATED
    capability_id: str = ""
    input_channels: List[str] = field(default_factory=list)
    form_fields: List[str] = field(default_factory=list)
    verifier_implementation_module: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PlanItem:
    candidate_id: str
    path: str
    method: str
    family: str
    probe_family: str
    capability_id: str
    capability_maturity_before: str
    support_classification: str
    classification: str
    must_not_confirm: bool
    modes: List[str]
    parameter: str
    input_channels: List[str]
    schedule_status: str
    exclusion_reason: str = ""
    requires: List[str] = field(default_factory=list)
    verifier_implementation_module: str = ""
    url: str = ""
    form_fields: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def normalize_family(family: str) -> str:
    fam = (family or "").strip().lower()
    return FAMILY_ALIASES.get(fam, fam)


def family_requires(family: str) -> List[str]:
    fam = normalize_family(family)
    mat = assess_capability_maturity(fam)
    req = list(mat.get("requires") or [])
    if fam == "dom_clobber" and "browser" not in req:
        req.append("browser")
    if fam == "ssrf" and "callback_base_or_oob" not in req:
        req.append("callback_base_or_oob")
    if fam == "cors":
        if "browser" not in req:
            req.append("browser")
        if "cors_proof_origin" not in req:
            req.append("cors_proof_origin")
    return req


def build_execution_plan(
    *,
    mode: str,
    surfaces: Sequence[CandidateSurface],
    deps: DependencyAvailability,
    ignore_stale_live_marks: bool = True,
) -> List[PlanItem]:
    """Build a capability-driven plan for one scan mode from discovered surfaces.

    Registry membership alone never marks a candidate scheduled or verified —
    schedule_status reflects mode, adapter executability, and dependencies only.
    """
    mode_n = (mode or "safe").strip().lower()
    items: List[PlanItem] = []
    for surf in surfaces:
        if str(surf.support_classification or "") not in ("supported_active", "applicable", ""):
            # Still allow explicit supported_active; skip passive/unsupported
            if str(surf.support_classification or "") not in ("supported_active",):
                continue
        family = normalize_family(surf.family or surf.probe_family)
        if not family:
            continue
        maturity = str(surf.capability_maturity or MATURITY_EXECUTABLE_UNVALIDATED)
        if ignore_stale_live_marks and maturity == MATURITY_LIVE_VALIDATED:
            maturity_for_plan = MATURITY_EXECUTABLE_UNVALIDATED
        else:
            maturity_for_plan = maturity

        modes = [str(m).lower() for m in (surf.modes or [])]
        path = str(surf.path or "")
        verifier = get_verifier(family)
        requires = family_requires(family)
        cap_id = str(surf.capability_id or "") or (verifier.capability_id if verifier else "")

        item = PlanItem(
            candidate_id=str(surf.candidate_id or f"surf:{path}:{family}"),
            path=path,
            method=str(surf.method or "GET"),
            family=family,
            probe_family=str(surf.probe_family or family),
            capability_id=cap_id,
            capability_maturity_before=maturity_for_plan,
            support_classification=str(surf.support_classification or "supported_active"),
            classification=str(surf.classification or "vulnerable"),
            must_not_confirm=bool(surf.must_not_confirm),
            modes=modes,
            parameter=str(surf.parameter or ""),
            input_channels=list(surf.input_channels or []),
            schedule_status=ATTEMPTED,
            requires=requires,
            verifier_implementation_module=str(
                surf.verifier_implementation_module
                or (assess_capability_maturity(family).get("implementation_module") or "")
            ),
            url=str(surf.url or ""),
            form_fields=list(surf.form_fields or []),
        )

        if modes and mode_n not in modes:
            item.schedule_status = MODE_EXCLUDED
            item.exclusion_reason = f"mode_excluded:{mode_n}_not_in_{modes}"
            items.append(item)
            continue

        if verifier is None:
            item.schedule_status = NO_EXECUTABLE_ADAPTER
            item.exclusion_reason = f"no_verifier_for_family:{family}"
            items.append(item)
            continue

        assessed = assess_capability_maturity(family)
        if not assessed.get("executable_methods"):
            item.schedule_status = NO_EXECUTABLE_ADAPTER
            item.exclusion_reason = "registered_without_executable_lifecycle"
            items.append(item)
            continue

        if family == "dom_clobber" and mode_n in ("extended", "lab") and not deps.browser:
            item.schedule_status = DEPENDENCY_UNAVAILABLE
            item.exclusion_reason = "dependency_unavailable:browser"
            items.append(item)
            continue

        if family == "cors" and mode_n in ("extended", "lab"):
            if not deps.browser:
                item.schedule_status = DEPENDENCY_UNAVAILABLE
                item.exclusion_reason = "dependency_unavailable:browser"
                items.append(item)
                continue
            if not deps.cors_proof_origin:
                item.schedule_status = DEPENDENCY_UNAVAILABLE
                item.exclusion_reason = "dependency_unavailable:cors_proof_origin"
                items.append(item)
                continue

        if family == "ssrf" and not deps.oob_callback and mode_n in ("extended", "lab"):
            item.requires = list(set(requires + ["callback_base_or_oob"]))

        item.schedule_status = ATTEMPTED
        item.exclusion_reason = ""
        items.append(item)

    return items


def plan_summary(items: Sequence[PlanItem]) -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    for it in items:
        counts[it.schedule_status] = counts.get(it.schedule_status, 0) + 1
    return {
        "total_plan_items": len(items),
        "by_status": counts,
        "attempted": sum(1 for it in items if it.schedule_status == ATTEMPTED),
        "applicable_executable": len(items),
    }


# Backward-compatible alias used by benchmark wrappers
build_phase1_execution_plan_from_surfaces = build_execution_plan

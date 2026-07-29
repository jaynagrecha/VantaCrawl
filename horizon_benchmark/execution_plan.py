"""Benchmark adapter over the production-neutral Phase-1 execution planner.

Horizon inventory fixtures are converted to CandidateSurface objects here.
Production code must import verifiers.runtime.execution_plan instead.
"""

from __future__ import annotations

from typing import Any, Dict, List

from verifiers.maturity import MATURITY_EXECUTABLE_UNVALIDATED, MATURITY_LIVE_VALIDATED
from verifiers.runtime.execution_plan import (
    ATTEMPTED,
    BREAKER_PAUSED,
    DEPENDENCY_UNAVAILABLE,
    DISCOVERY_MISSING,
    DependencyAvailability,
    MODE_EXCLUDED,
    NO_EXECUTABLE_ADAPTER,
    PlanItem,
    TRANSPORT_FAILED,
    VERIFICATION_FAILED,
    CandidateSurface,
    build_execution_plan,
    normalize_family,
    plan_summary,
)

__all__ = [
    "ATTEMPTED",
    "BREAKER_PAUSED",
    "DEPENDENCY_UNAVAILABLE",
    "DISCOVERY_MISSING",
    "DependencyAvailability",
    "MODE_EXCLUDED",
    "NO_EXECUTABLE_ADAPTER",
    "PlanItem",
    "TRANSPORT_FAILED",
    "VERIFICATION_FAILED",
    "build_phase1_execution_plan",
    "plan_summary",
]


def _fixture_to_surface(fix: Dict[str, Any]) -> CandidateSurface:
    tags = {str(t).lower() for t in (fix.get("catalog_tags") or [])}
    path = str(fix.get("path") or "")
    family = normalize_family(str(fix.get("probe_family") or fix.get("family") or ""))
    # Benchmark-only: inventory may tag DOM-clobber surfaces
    if "dom-clobber" in tags or "dom_clobber" in family or "dom-clobber" in path:
        family = "dom_clobber"
    return CandidateSurface(
        candidate_id=str(fix.get("fixture_id") or f"hz:{path}"),
        url=str(fix.get("url") or ""),
        path=path,
        method=str(fix.get("method") or "GET"),
        family=family,
        probe_family=str(fix.get("probe_family") or family),
        parameter=str(fix.get("parameter") or ""),
        classification=str(fix.get("classification") or "vulnerable"),
        must_not_confirm=bool(fix.get("must_not_confirm")),
        modes=[str(m).lower() for m in (fix.get("modes") or [])],
        support_classification=str(fix.get("support_classification") or "supported_active"),
        capability_maturity=str(
            fix.get("capability_maturity") or MATURITY_EXECUTABLE_UNVALIDATED
        ),
        capability_id=str(fix.get("verifier_capability_id") or ""),
        input_channels=list(fix.get("input_channels") or []),
        verifier_implementation_module=str(fix.get("verifier_implementation_module") or ""),
    )


def build_phase1_execution_plan(
    *,
    mode: str,
    inventory: Dict[str, Any],
    deps: DependencyAvailability,
    ignore_stale_live_marks: bool = True,
) -> List[PlanItem]:
    surfaces = [
        _fixture_to_surface(fix)
        for fix in (inventory.get("fixtures") or [])
        if str(fix.get("support_classification") or "") == "supported_active"
    ]
    # Normalize stale live marks before planning
    if ignore_stale_live_marks:
        for s in surfaces:
            if s.capability_maturity == MATURITY_LIVE_VALIDATED:
                s.capability_maturity = MATURITY_EXECUTABLE_UNVALIDATED
    return build_execution_plan(
        mode=mode, surfaces=surfaces, deps=deps, ignore_stale_live_marks=ignore_stale_live_marks
    )

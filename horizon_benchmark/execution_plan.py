"""Generic Phase-1 execution planner — capability-driven, not route-list-driven.

Selects work from inventory support classification + verifier registry + mode
and dependency availability. Benchmark catalog paths are measurement surfaces
loaded from the inventory; this module must not introduce Horizon-specific
production hardcodes into scanner packages.
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


@dataclass
class DependencyAvailability:
    http_client: bool = True
    browser: bool = False
    oob_callback: bool = False
    traversal_canary: bool = False
    session: bool = False


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
    classification: str  # vulnerable | control | …
    must_not_confirm: bool
    modes: List[str]
    parameter: str
    input_channels: List[str]
    schedule_status: str
    exclusion_reason: str = ""
    requires: List[str] = field(default_factory=list)
    verifier_implementation_module: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _normalize_family(fix: Dict[str, Any]) -> str:
    tags = {str(t).lower() for t in (fix.get("catalog_tags") or [])}
    path = str(fix.get("path") or "")
    family = str(fix.get("probe_family") or fix.get("family") or "").lower()
    if "dom-clobber" in path or "dom_clobber" in family or "dom-clobber" in tags:
        return "dom_clobber"
    aliases = {
        "command_injection": "rce",
        "open_redirect": "redirect",
        "lfi": "traversal",
        "header_injection": "crlf",
    }
    return aliases.get(family, family)


def _family_requires(family: str, fix: Dict[str, Any]) -> List[str]:
    mat = assess_capability_maturity(family, path=str(fix.get("path") or ""))
    req = list(mat.get("requires") or [])
    # Browser-tagged inventory surfaces need browser in lab/extended for XSS confirm
    channels = {str(c).lower() for c in (fix.get("input_channels") or [])}
    tags_hint = "browser" in channels or family in ("dom_clobber", "xss")
    if family == "dom_clobber" and "browser" not in req:
        req.append("browser")
    if family == "ssrf" and "callback_base_or_oob" not in req:
        req.append("callback_base_or_oob")
    if family in ("traversal", "lfi") and "traversal_canary_or_diff" not in req:
        # canary preferred in lab; differential still executable without canary
        pass
    if tags_hint and family == "xss" and "browser" not in req:
        # XSS may still run reflection without browser; browser only required for
        # browser_execution_confirmed tier — not a hard schedule dependency.
        pass
    return req


def _deps_ok(requires: Sequence[str], deps: DependencyAvailability, mode: str) -> tuple[bool, str]:
    missing: List[str] = []
    for r in requires:
        if r in ("callback_base_or_oob", "oob") and not deps.oob_callback:
            missing.append("oob_callback")
        elif r == "browser" and not deps.browser:
            # DOM clobber needs browser for terminal proof; still attempt discovery
            # in safe without browser but mark dependency for live-recall denom.
            if mode in ("extended", "lab"):
                missing.append("browser")
        elif r == "traversal_canary_or_diff":
            # Not hard-blocking — differential path remains
            continue
        elif r == "session" and not deps.session:
            missing.append("session")
        elif r == "http_client" and not deps.http_client:
            missing.append("http_client")
    if missing:
        return False, "dependency_unavailable:" + ",".join(sorted(set(missing)))
    return True, ""


def build_phase1_execution_plan(
    *,
    mode: str,
    inventory: Dict[str, Any],
    deps: DependencyAvailability,
    ignore_stale_live_marks: bool = True,
) -> List[PlanItem]:
    """Build capability-driven plan for one scan mode.

    Includes every supported_active fixture whose pre-run maturity is executable
    (executable_unvalidated or live_validated). Stale live_validated marks are
    normalized to executable_unvalidated for scheduling when
    ``ignore_stale_live_marks`` is True — they do not grant credit.
    """
    mode_n = (mode or "safe").strip().lower()
    items: List[PlanItem] = []
    for fix in inventory.get("fixtures") or []:
        if str(fix.get("support_classification") or "") != "supported_active":
            continue
        family = _normalize_family(fix)
        maturity = str(fix.get("capability_maturity") or "")
        if ignore_stale_live_marks and maturity == MATURITY_LIVE_VALIDATED:
            maturity_for_plan = MATURITY_EXECUTABLE_UNVALIDATED
        else:
            maturity_for_plan = maturity
        if maturity_for_plan not in EXECUTABLE_MATURITIES and maturity not in EXECUTABLE_MATURITIES:
            # supported_active should already be executable; skip non-executable
            continue

        modes = [str(m).lower() for m in (fix.get("modes") or [])]
        path = str(fix.get("path") or "")
        cap_id = str(fix.get("verifier_capability_id") or "")
        verifier = get_verifier(family)
        requires = _family_requires(family, fix)

        item = PlanItem(
            candidate_id=str(fix.get("fixture_id") or f"hz:{path}"),
            path=path,
            method=str(fix.get("method") or "GET"),
            family=family,
            probe_family=str(fix.get("probe_family") or family),
            capability_id=cap_id or (verifier.capability_id if verifier else ""),
            capability_maturity_before=maturity_for_plan,
            support_classification="supported_active",
            classification=str(fix.get("classification") or ""),
            must_not_confirm=bool(fix.get("must_not_confirm")),
            modes=modes,
            parameter=str(fix.get("parameter") or ""),
            input_channels=list(fix.get("input_channels") or []),
            schedule_status=ATTEMPTED,
            requires=requires,
            verifier_implementation_module=str(
                fix.get("verifier_implementation_module")
                or (assess_capability_maturity(family, path=path).get("implementation_module") or "")
            ),
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

        assessed = assess_capability_maturity(family, path=path)
        if not assessed.get("executable_methods"):
            item.schedule_status = NO_EXECUTABLE_ADAPTER
            item.exclusion_reason = "registered_without_executable_lifecycle"
            items.append(item)
            continue

        # Hard dependency: DOM clobber terminal path needs browser in extended/lab.
        # Still schedule attempt in safe (HTTP injection ladder) without browser.
        if family == "dom_clobber" and mode_n in ("extended", "lab") and not deps.browser:
            item.schedule_status = DEPENDENCY_UNAVAILABLE
            item.exclusion_reason = "dependency_unavailable:browser"
            items.append(item)
            continue

        if family == "ssrf" and not deps.oob_callback and mode_n in ("extended", "lab"):
            # SSRF may still run reflection probes; keep attempted but note dep for denom
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

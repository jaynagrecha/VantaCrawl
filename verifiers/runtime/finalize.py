"""Finalize Phase-1 planner + lifecycle for a production scan.

Invoked from the report writer after active probes have run. Builds an
execution plan from discovered surfaces, maps request-ledger evidence into
canonical lifecycle rows, publishes metrics, and writes artifacts.
"""

from __future__ import annotations

import traceback
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from verifiers.contract import CONFIRMED_ACTIVE_STATES, is_actively_confirmed
from verifiers.maturity import (
    MATURITY_EXECUTABLE_UNVALIDATED,
    clear_live_validated,
)
from verifiers.registry import capability_registry
from verifiers.runtime.artifacts import write_phase1_artifacts
from verifiers.runtime.execution_plan import (
    ATTEMPTED,
    DISCOVERY_MISSING,
    DependencyAvailability,
    PlanItem,
    build_execution_plan,
    normalize_family,
    plan_summary,
)
from verifiers.runtime.lifecycle import (
    OUTCOME_NONTERMINAL,
    apply_probe_outcome,
    classify_lifecycle_outcome,
    compute_published_metrics,
    empty_lifecycle_row,
    proof_type_for_state,
)
from verifiers.runtime.surfaces import discover_surfaces_from_stats


# Prefer stronger terminal states when multiple ledger rows exist for one candidate.
_STATE_RANK = {
    "browser_execution_confirmed": 100,
    "server_execution_confirmed": 95,
    "execution_confirmed": 95,
    "oob_callback_confirmed": 90,
    "canary_file_confirmed": 90,
    "controlled_request_confirmed": 85,
    "html_injection_confirmed": 40,
    "html_injection": 28,
    "differential_signal": 35,
    "reflected_only": 30,
    "clobbered_value_consumed": 25,
    "sink_context_candidate": 20,
    "attribute_breakout": 20,
    "marker_output_signal": 15,
    "negative": 10,
    "probe_sent": 5,
    "inconclusive": 8,
    "confirmation_unavailable": 8,
}


def _path(url: str) -> str:
    try:
        return urlparse(url).path or "/"
    except Exception:
        return "/"


def _deps_from_config_stats(config: Any, stats: Any) -> DependencyAvailability:
    browser = False
    try:
        bc = getattr(stats, "browser_confirmation", None) or {}
        browser = str(bc.get("browser_confirmation") or "") == "available"
    except Exception:
        browser = False
    oob = False
    try:
        base = str(getattr(config, "ssrf_callback_base", "") or "")
        poll = str(getattr(config, "oob_callback_poll_url", "") or "")
        oob = bool(base or poll)
    except Exception:
        oob = False
    canary = bool(getattr(config, "traversal_fixture_installed", False))
    return DependencyAvailability(
        http_client=True,
        browser=browser,
        oob_callback=oob,
        traversal_canary=canary,
        session=False,
    )


def _best_state(states: List[str]) -> str:
    best = ""
    best_rank = -1
    for st in states:
        s = str(st or "").strip()
        if not s:
            continue
        rank = _STATE_RANK.get(s, 1)
        if rank > best_rank:
            best_rank = rank
            best = s
    return best


def _ledger_for_candidate(
    ledger: List[Dict[str, Any]],
    *,
    path: str,
    family: str,
) -> List[Dict[str, Any]]:
    fam = normalize_family(family)
    out = []
    for row in ledger:
        if str(row.get("phase") or "") != "active_probe":
            continue
        row_fam = normalize_family(str(row.get("probe_class") or ""))
        if row_fam != fam:
            continue
        if _path(str(row.get("url") or row.get("final_url") or "")) != path:
            continue
        out.append(row)
    return out


def _finding_for_candidate(findings: List[Any], *, path: str, family: str) -> bool:
    fam = normalize_family(family)
    for f in findings:
        if not isinstance(f, dict):
            continue
        fpath = _path(str(f.get("url") or ""))
        if fpath != path:
            continue
        cat = normalize_family(str(f.get("category") or f.get("family") or ""))
        if cat == fam or fam in cat or cat in fam:
            return True
        # Finding may use display names
        if fam and fam in str(f.get("category") or "").lower():
            return True
    return False


def apply_ledger_to_lifecycle(
    plan_items: List[PlanItem],
    *,
    mode: str,
    ledger: List[Dict[str, Any]],
    findings: List[Any],
    scan_id: str,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in plan_items:
        d = item.to_dict()
        row = empty_lifecycle_row(
            plan_item={
                **d,
                "exclusion_reason": d.get("exclusion_reason") or "",
            },
            mode=mode,
            discovered_url=str(d.get("url") or ""),
        )
        row["scan_id"] = scan_id
        row["run_validation_outcome"] = ""  # per-run; never mutates static registry
        row["form_submitted"] = False
        row["route_visited"] = False
        if item.schedule_status != ATTEMPTED:
            row["lifecycle_outcome"] = classify_lifecycle_outcome(row)
            rows.append(row)
            continue

        hits = _ledger_for_candidate(ledger, path=item.path, family=item.family)
        probes = [h for h in hits if h.get("probe_role") == "probe"]
        controls = [h for h in hits if h.get("probe_role") == "control"]
        baselines = [h for h in hits if h.get("probe_role") == "baseline"]
        replays = [h for h in hits if h.get("probe_role") == "replay"]
        form_hits = [
            h
            for h in hits
            if str(h.get("method") or "").upper() == "POST"
            or str(h.get("probe_role") or "") in ("form_submit", "form")
            or bool(h.get("form_submitted"))
        ]
        browser_hits = [
            h
            for h in hits
            if str(h.get("probe_role") or "").startswith("browser")
            or h.get("result_state") in ("browser_execution_confirmed", "browser_execution_failed")
        ]
        # Route visit alone (crawl phase) never counts as verification — only active_probe hits.
        row["route_visited"] = bool(hits)
        row["form_submitted"] = bool(form_hits) or bool(item.form_fields and form_hits)
        states = [str(h.get("result_state") or "") for h in probes] or [
            str(h.get("result_state") or "") for h in hits
        ]
        best = _best_state(states)
        # If probes ran but state empty → probe_sent nonterminal
        probe_sent = bool(probes) or any(
            h.get("probe_role") in ("probe", "replay") for h in hits
        )
        if probe_sent and not best:
            best = "probe_sent"
        # Catalog-seeded plan items with no active-probe evidence were scheduled
        # but not executed — do not inflate execution / lifecycle denominators.
        if not probe_sent and not hits:
            row["schedule_status"] = DISCOVERY_MISSING
            row["failure_or_exclusion_reason"] = (
                row.get("failure_or_exclusion_reason") or "planned_but_not_executed_in_scan"
            )
            row["lifecycle_outcome"] = classify_lifecycle_outcome(row)
            row["unresolved_reason"] = "planned_but_not_executed_in_scan"
            row["run_validation_outcome"] = row["lifecycle_outcome"]
            rows.append(row)
            continue
        oob_used = any(
            "oob" in str(h.get("result_state") or "")
            or "callback" in str(h.get("probe_name") or "").lower()
            for h in hits
        )
        # Bind OOB evidence to this scan_id when ledger carries scan/nonce metadata
        oob_scan_ok = True
        for h in hits:
            ev_sid = str(h.get("scan_id") or h.get("oob_scan_id") or "")
            if ev_sid and ev_sid != scan_id:
                oob_scan_ok = False
        if oob_used and not oob_scan_ok:
            oob_used = False
            if best == "oob_callback_confirmed":
                best = "probe_sent"
        apply_probe_outcome(
            row,
            probe_sent=probe_sent,
            result_state=best,
            finding_emitted=_finding_for_candidate(findings, path=item.path, family=item.family),
            evidence={
                "baseline_count": len(baselines),
                "control_count": len(controls),
                "replay_count": len(replays),
                "browser_used": bool(browser_hits),
                "form_submitted": bool(form_hits),
                "submitted_fields": {f: True for f in (item.form_fields or [])},
                "scan_id": scan_id,
            },
            browser_used=bool(browser_hits),
            callback_used=oob_used,
        )
        if item.family == "ssrf" and not oob_used and best not in CONFIRMED_ACTIVE_STATES:
            # Keep deps flag honest for live-recall denominator
            row["deps_available_for_live_recall"] = row.get("deps_available_for_live_recall", True)
        row["run_validation_outcome"] = row.get("lifecycle_outcome") or OUTCOME_NONTERMINAL
        rows.append(row)
    return rows


def finalize_phase1_runtime(
    stats: Any,
    *,
    config: Any = None,
    report_dir: str = "",
    scan_id: str = "",
    output_callback=None,
) -> Dict[str, Any]:
    """Run planner + lifecycle finalize for one completed production scan.

    Never raises into the caller for planner failures — returns a degraded
    status payload and writes an explicit runtime gap artifact instead.
    """
    cb = output_callback or (lambda _m: None)
    # Fresh run — do not preload stale live_validated marks into this scan.
    clear_live_validated()

    sid = str(
        scan_id
        or getattr(stats, "scan_id", "")
        or getattr(config, "job_id", "")
        or getattr(config, "report_title", "")
        or "scan"
    )
    mode = "safe"
    try:
        from active_probe_kit import normalize_mode

        mode = normalize_mode(str(getattr(config, "active_probe_mode", "safe") or "safe"))
    except Exception:
        mode = str(getattr(config, "active_probe_mode", "safe") or "safe")

    runtime_status: Dict[str, Any] = {
        "status": "ok",
        "scan_id": sid,
        "mode": mode,
        "planner": "verifiers.runtime.execution_plan.build_execution_plan",
        "lifecycle": "verifiers.runtime.lifecycle.compute_published_metrics",
    }
    try:
        deps = _deps_from_config_stats(config, stats)
        surfaces = discover_surfaces_from_stats(stats, mode=mode, scan_id=sid)
        # Namespace candidate IDs with scan_id for isolation across concurrent jobs
        for s in surfaces:
            if not str(s.candidate_id).startswith(f"{sid}:"):
                s.candidate_id = f"{sid}:{s.candidate_id}"

        plan_items = build_execution_plan(mode=mode, surfaces=surfaces, deps=deps)
        ledger = list(getattr(stats, "request_ledger", None) or [])
        findings = list(getattr(stats, "findings", None) or [])
        lifecycle = apply_ledger_to_lifecycle(
            plan_items, mode=mode, ledger=ledger, findings=findings, scan_id=sid
        )
        published = compute_published_metrics(
            lifecycle,
            mode=mode,
            catalog_support_counts={
                "supported_active": max(
                    len(
                        [
                            r
                            for r in lifecycle
                            if r.get("support_classification") == "supported_active"
                        ]
                    ),
                    len(
                        [
                            s
                            for s in surfaces
                            if s.support_classification == "supported_active"
                        ]
                    ),
                )
            },
        )
        # Per-run outcomes only — never mutate static registry maturity files.
        published["scan_id"] = sid
        published["stale_live_validated_preloaded"] = False

        caps = capability_registry()
        capability_inventory = {
            "scan_id": sid,
            "mode": mode,
            "capabilities": caps,
            "surface_count": len(surfaces),
            "plan_summary": plan_summary(plan_items),
        }
        unresolved = []
        for row in lifecycle:
            if row.get("lifecycle_outcome") == OUTCOME_NONTERMINAL or row.get("unresolved_reason"):
                if row.get("schedule_status") == ATTEMPTED or row.get("unresolved_reason"):
                    unresolved.append(
                        {
                            "candidate_id": row.get("fixture_id"),
                            "path": row.get("path"),
                            "family": row.get("family"),
                            "result_state": row.get("terminal_result_state"),
                            "outcome": row.get("lifecycle_outcome"),
                            "reason": row.get("unresolved_reason")
                            or row.get("failure_or_exclusion_reason"),
                        }
                    )
        evidence_prov = [
            {
                "candidate_id": r.get("fixture_id"),
                "path": r.get("path"),
                "family": r.get("family"),
                "provenance": r.get("evidence_provenance"),
                "proof_type": proof_type_for_state(str(r.get("terminal_result_state") or "")),
                "scan_id": sid,
            }
            for r in lifecycle
            if r.get("probe_sent") or r.get("terminal_result_state")
        ]

        artifact_paths: Dict[str, str] = {}
        if report_dir:
            artifact_paths = write_phase1_artifacts(
                report_dir,
                execution_plan=[p.to_dict() for p in plan_items],
                lifecycle_rows=lifecycle,
                published_metrics=published,
                capability_inventory=capability_inventory,
                unresolved_gaps=unresolved,
                evidence_provenance=evidence_prov,
                runtime_status=runtime_status,
                request_ledger=ledger,
            )

        # Attach summary onto stats for job progress / API consumers (additive).
        summary = {
            "phase1_runtime_status": runtime_status["status"],
            "scan_id": sid,
            "mode": mode,
            "execution_plan_count": len(plan_items),
            "lifecycle_row_count": len(lifecycle),
            "lifecycle_completion_coverage": published.get("lifecycle_completion_coverage"),
            "applicable_execution_coverage": published.get("applicable_execution_coverage"),
            "scheduling_coverage": published.get("scheduling_coverage"),
            "evidence_backed_live_recall": {
                k: v
                for k, v in (published.get("evidence_backed_live_recall") or {}).items()
                if k != "live_validated_entries"
            },
            "negative_control_fp_rate": published.get("negative_control_fp_rate"),
            "nonterminal_rate": {
                k: v for k, v in (published.get("nonterminal_rate") or {}).items() if k != "rows"
            },
            "outcome_class_counts_attempted": published.get("outcome_class_counts_attempted"),
            "artifact_paths": artifact_paths,
        }
        try:
            setattr(stats, "phase1_runtime_summary", summary)
            setattr(stats, "phase1_lifecycle_rows", lifecycle)
            setattr(stats, "phase1_published_metrics", published)
        except Exception:
            pass
        cb(
            f"Phase-1 runtime: plan={len(plan_items)} lifecycle={len(lifecycle)} "
            f"completion={summary.get('lifecycle_completion_coverage')}"
        )
        return {
            "runtime_status": runtime_status,
            "execution_plan": [p.to_dict() for p in plan_items],
            "lifecycle_rows": lifecycle,
            "published_metrics": published,
            "summary": summary,
            "artifact_paths": artifact_paths,
        }
    except Exception as exc:
        runtime_status = {
            "status": "failed",
            "scan_id": sid,
            "mode": mode,
            "error": str(exc),
            "traceback": traceback.format_exc()[-2000:],
        }
        try:
            setattr(stats, "phase1_runtime_summary", {"phase1_runtime_status": "failed", "error": str(exc)})
        except Exception:
            pass
        if report_dir:
            try:
                write_phase1_artifacts(
                    report_dir,
                    execution_plan=[],
                    lifecycle_rows=[],
                    published_metrics={},
                    capability_inventory={},
                    unresolved_gaps=[
                        {
                            "reason": "phase1_runtime_error",
                            "error": str(exc),
                        }
                    ],
                    evidence_provenance=[],
                    runtime_status=runtime_status,
                )
            except Exception:
                pass
        cb(f"Phase-1 runtime degraded: {exc}")
        return {
            "runtime_status": runtime_status,
            "execution_plan": [],
            "lifecycle_rows": [],
            "published_metrics": {},
            "summary": {"phase1_runtime_status": "failed", "error": str(exc)},
            "artifact_paths": {},
        }

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
    "cors_browser_read_confirmed": 100,
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
    cors_proof = False
    try:
        base = str(getattr(config, "cors_proof_origin_base", "") or "").strip()
        secret = str(getattr(config, "cors_proof_secret", "") or "").strip()
        cors_proof = bool(base and secret)
    except Exception:
        cors_proof = False
    return DependencyAvailability(
        http_client=True,
        browser=browser,
        oob_callback=oob,
        traversal_canary=canary,
        session=False,
        cors_proof_origin=cors_proof,
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
        probes = [
            h
            for h in hits
            if h.get("probe_role")
            in ("probe", "cors_browser_proof", "cors_classified", "cors_browser_read_confirmed")
        ]
        controls = [
            h
            for h in hits
            if h.get("probe_role") in ("control", "cors_negative_control")
        ]
        baselines = [h for h in hits if h.get("probe_role") == "baseline"]
        replays = [
            h for h in hits if h.get("probe_role") in ("replay", "cors_replay")
        ]
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
            or str(h.get("probe_role") or "").startswith("cors_")
            or h.get("result_state")
            in (
                "browser_execution_confirmed",
                "browser_execution_failed",
                "cors_browser_read_confirmed",
            )
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
            h.get("probe_role")
            in ("probe", "replay", "cors_browser_proof", "cors_replay", "cors_classified", "cors_browser_read_confirmed")
            for h in hits
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


def _inventory_identities_from_stats(stats: Any) -> List[Dict[str, Any]]:
    """Build ground-truth inventory identities from target catalog.json when present.

    Uses maturity classification plus catalog-tag demotion from
    ``verifiers.policy.catalog_inventory`` (path-independent). Never imports
    benchmark packages or fixture route tables.
    """
    catalog = list(getattr(stats, "target_catalog", None) or [])
    if not catalog:
        return []
    from verifiers.policy.catalog_inventory import catalog_entry_demotion_reason

    out: List[Dict[str, Any]] = []
    seen: set = set()
    for entry in catalog:
        if not isinstance(entry, dict):
            continue
        path = str(entry.get("path") or "")
        if not path.startswith("/"):
            continue
        tags = {str(t).lower() for t in (entry.get("tags") or entry.get("catalog_tags") or [])}
        fam = normalize_family(str(entry.get("family") or entry.get("probe_family") or ""))
        if "dom-clobber" in tags or "dom_clobber" in fam:
            fam = "dom_clobber"
        if fam not in (
            "sqli",
            "rce",
            "ssti",
            "xss",
            "ssrf",
            "redirect",
            "traversal",
            "crlf",
            "csrf",
            "dom_clobber",
            "lfi",
            "command_injection",
        ):
            continue
        from verifiers.maturity import classify_support_from_maturity

        path_reason = catalog_entry_demotion_reason(entry)
        support = classify_support_from_maturity(
            bucket="supported"
            if (
                "active" in tags
                or "safe" in tags
                or "lab" in tags
                or "extended" in tags
                or "control" in tags
                or "oob" in tags
                or "dom-clobber" in tags
            )
            else "passive",
            family=fam,
            path=path,
            path_demotion_reason=path_reason,
        )
        if support.get("support_classification") != "supported_active":
            continue
        if path in seen:
            continue
        seen.add(path)
        is_control = "control" in tags or str(entry.get("classification") or "").lower() == "control"
        # Generic leaf /safe control marker (no fixture-path table).
        leaf = path.rstrip("/").rsplit("/", 1)[-1]
        if leaf == "safe" or path.rstrip("/").endswith("-safe"):
            is_control = True
        out.append(
            {
                "path": path,
                "fixture_id": f"inv:{path}",
                "family": fam if fam != "lfi" else "traversal",
                "classification": "control" if is_control else "vulnerable",
                "must_not_confirm": is_control,
            }
        )
    return out


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
        inventory_identities = _inventory_identities_from_stats(stats)
        published = compute_published_metrics(
            lifecycle,
            mode=mode,
            catalog_support_counts={
                "supported_active": (
                    len(inventory_identities)
                    if inventory_identities
                    else max(
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
                )
            },
            inventory_identities=inventory_identities or None,
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
        evidence_prov = []
        for r in lifecycle:
            if not (r.get("probe_sent") or r.get("terminal_result_state")):
                continue
            path = str(r.get("path") or "")
            fam = normalize_family(str(r.get("family") or ""))
            browser_rows = [
                h
                for h in ledger
                if str(h.get("phase") or "") == "active_probe"
                and normalize_family(str(h.get("probe_class") or "")) == fam
                and _path(str(h.get("url") or h.get("final_url") or "")) == path
                and (
                    str(h.get("probe_role") or "").startswith("browser")
                    or "browser" in str(h.get("result_state") or "")
                )
            ]
            probe_rows = [
                h
                for h in ledger
                if str(h.get("phase") or "") == "active_probe"
                and h.get("probe_role") == "probe"
                and normalize_family(str(h.get("probe_class") or "")) == fam
                and _path(str(h.get("url") or h.get("final_url") or "")) == path
            ]
            # Prefer the probe that was actually accepted for confirmation —
            # never substitute a later sibling probe for the same candidate.
            confirming_browser = next(
                (
                    h
                    for h in browser_rows
                    if str(h.get("probe_role") or "") == "browser_execution_confirmed"
                ),
                None,
            )
            if confirming_browser is None:
                confirming_browser = next(
                    (
                        h
                        for h in browser_rows
                        if str(h.get("result_state") or "") == "browser_execution_confirmed"
                        and str(h.get("probe_role") or "").startswith("browser")
                    ),
                    None,
                )
            if confirming_browser is None:
                confirming_browser = next(
                    (
                        h
                        for h in browser_rows
                        if str(h.get("result_state") or "") == "browser_execution_confirmed"
                    ),
                    None,
                )
            confirming_probe_id = (
                str((confirming_browser or {}).get("probe_id") or "") if confirming_browser else ""
            )
            confirming_nonce = (
                str((confirming_browser or {}).get("nonce") or "") if confirming_browser else ""
            )
            confirming_probe = None
            if confirming_probe_id:
                confirming_probe = next(
                    (
                        h
                        for h in probe_rows
                        if str(h.get("probe_id") or "") == confirming_probe_id
                    ),
                    None,
                )
            if confirming_probe is None and confirming_nonce:
                confirming_probe = next(
                    (
                        h
                        for h in probe_rows
                        if str(h.get("nonce") or "") == confirming_nonce
                    ),
                    None,
                )
            if confirming_probe is None and confirming_browser is None:
                # No browser confirmation — keep latest probe for negative traces,
                # but do not invent a confirming identity.
                confirming_probe = probe_rows[-1] if probe_rows else {}
                confirming_browser = {}
            elif confirming_probe is None:
                confirming_probe = {}

            marker_row = next(
                (
                    h
                    for h in browser_rows
                    if str(h.get("probe_role") or "") == "browser_marker_checked"
                    and (
                        not confirming_probe_id
                        or str(h.get("probe_id") or "") == confirming_probe_id
                    )
                ),
                confirming_browser or {},
            )
            context_row = confirming_browser or next(
                (
                    h
                    for h in browser_rows
                    if h.get("browser_context_id") or h.get("browser_request_id")
                ),
                {},
            )
            terminal_state = str(r.get("terminal_result_state") or "")
            if terminal_state == "browser_execution_confirmed" and confirming_browser:
                decision = "confirmed_current_probe"
            elif browser_rows:
                decision = "rejected_or_absent"
            else:
                decision = "no_browser_attempt"
            # Prefer confirming ledger candidate_id so provenance matches the
            # accepted probe identity (same scan_id + candidate_id as ledger).
            confirming_cid = str(
                (confirming_browser or {}).get("candidate_id")
                or (confirming_probe or {}).get("candidate_id")
                or r.get("fixture_id")
                or ""
            )
            if confirming_cid and not confirming_cid.startswith(f"{sid}:"):
                confirming_cid = f"{sid}:{confirming_cid}"
            corr = {
                "scan_id": sid,
                "candidate_id": confirming_cid or r.get("fixture_id"),
                "probe_id": (confirming_probe or {}).get("probe_id")
                or (confirming_browser or {}).get("probe_id"),
                "nonce": (confirming_probe or {}).get("nonce")
                or (confirming_browser or {}).get("nonce"),
                "target_url": r.get("discovered_url"),
                "target_parameter": (confirming_probe or {}).get("parameter")
                or (confirming_browser or {}).get("parameter")
                or r.get("parameter"),
                "payload_redacted": (confirming_probe or {}).get("payload_redacted"),
                "browser_context_id": context_row.get("browser_context_id")
                or context_row.get("browser_request_id"),
                "marker_before": marker_row.get("marker_before"),
                "marker_after": marker_row.get("marker_after"),
                "correlation_reason": (confirming_browser or marker_row).get(
                    "correlation_reason"
                ),
                "terminal_result_state": terminal_state,
                "decision": decision,
            }
            evidence_prov.append(
                {
                    "candidate_id": confirming_cid or r.get("fixture_id"),
                    "path": r.get("path"),
                    "family": r.get("family"),
                    "provenance": r.get("evidence_provenance"),
                    "proof_type": proof_type_for_state(terminal_state),
                    "scan_id": sid,
                    "correlation": corr,
                    "raw_browser_evidence": [
                        {
                            "probe_role": h.get("probe_role"),
                            "result_state": h.get("result_state"),
                            "url": h.get("url"),
                            "probe_id": h.get("probe_id"),
                            "nonce": h.get("nonce"),
                            "scan_id": h.get("scan_id"),
                            "candidate_id": h.get("candidate_id"),
                        }
                        for h in browser_rows[-8:]
                    ],
                }
            )

        artifact_paths: Dict[str, str] = {}
        if report_dir:
            artifact_paths = write_phase1_artifacts(
                report_dir,
                execution_plan=[
                    {**p.to_dict(), "scan_id": sid} for p in plan_items
                ],
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

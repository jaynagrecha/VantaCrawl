"""Professional dual-audience assessment report model (client + security engineer)."""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from crawl_stats import CrawlStats
from finding_explain import group_findings_for_report
from report_time import format_dual
from search_report import build_search_conclusion


def _plain_severity_blurb(severity: str, title: str) -> str:
    sev = (severity or "info").lower()
    if sev == "critical":
        return f"Urgent: {title}. This should be treated as a top priority before further exposure."
    if sev == "high":
        return f"Important: {title}. Plan a fix in the near term; do not leave unreviewed."
    if sev == "medium":
        return f"Worth fixing: {title}. Address in the next hardening cycle."
    if sev == "low":
        return f"Low urgency: {title}. Track and fix when convenient."
    return f"Informational: {title}. Useful context for defenders; verify before acting."


def build_assessment_document(
    stats: CrawlStats,
    start_url: str,
    *,
    config_meta: Optional[Dict[str, Any]] = None,
    conclusion: Optional[Dict[str, Any]] = None,
    job_title: str = "",
    mode: str = "",
) -> Dict[str, Any]:
    meta = dict(config_meta or {})
    if conclusion is None:
        conclusion = build_search_conclusion(
            stats,
            start_url,
            profile=str(meta.get("profile") or "full"),
            download_enabled=bool(meta.get("download_files")),
            security_enabled=bool(meta.get("security_scan", True)),
            output_file=str(meta.get("output_file") or ""),
            download_dir=str(meta.get("download_dir") or ""),
            config_meta=meta,
        )

    model = conclusion.get("report_model") or {}
    groups = list(conclusion.get("finding_groups") or model.get("finding_groups") or [])
    if not groups and getattr(stats, "findings", None):
        groups = group_findings_for_report(list(stats.findings))

    sev = Counter(conclusion.get("severity_counts") or model.get("severity_counts") or {})
    snap = conclusion.get("snapshot") or model.get("snapshot") or stats.snapshot()
    defense = conclusion.get("defense") or model.get("defense") or {}
    host = urlparse(start_url).netloc or start_url

    findings_dual: List[Dict[str, Any]] = []
    vuln_i = 0
    hard_i = 0
    for group in groups:
        severity = str(group.get("severity") or "info")
        title = str(group.get("title") or group.get("detail") or "Finding")
        kind = str(group.get("finding_kind") or "vulnerability")
        if kind == "hardening":
            hard_i += 1
            fid = f"H-{hard_i:02d}"
        else:
            vuln_i += 1
            fid = f"V-{vuln_i:02d}"
        findings_dual.append(
            {
                "id": fid,
                "finding_kind": kind,
                "severity": severity,
                "category": str(group.get("category") or "other"),
                "title": title,
                "detail": str(group.get("detail") or ""),
                "count": int(group.get("count") or 0),
                "unique_hosts": int(group.get("unique_hosts") or 0),
                "urls": list(group.get("urls") or [])[:40],
                "evidence": list(group.get("evidence") or [])[:12],
                "role": str(group.get("role") or ""),
                "impact": str(group.get("impact") or ""),
                "validation": str(group.get("validation") or ""),
                "impact_summary": str(group.get("impact_summary") or ""),
                "verification": str(group.get("verification") or ""),
                "proof": dict(group.get("proof") or {}) if isinstance(group.get("proof"), dict) else {},
                "confidence": str(group.get("confidence") or ""),
                "confidence_reason": str(group.get("confidence_reason") or ""),
                "executive": _plain_severity_blurb(severity, title),
                "what": str(group.get("what") or ""),
                "attacker": str(group.get("attacker") or ""),
                "fix": str(group.get("fix") or ""),
            }
        )

    vulnerabilities = [f for f in findings_dual if f.get("finding_kind") != "hardening"]
    hardening_issues = [f for f in findings_dual if f.get("finding_kind") == "hardening"]

    from report_status import (
        assessment_state_for_finding,
        partial_executive_summary,
        scan_status_from_stats,
    )

    status_meta = scan_status_from_stats(stats)
    for f in findings_dual:
        f["assessment_state"] = assessment_state_for_finding(
            category=str(f.get("category") or ""),
            severity=str(f.get("severity") or ""),
            validation=str(f.get("validation") or ""),
            impact=str(f.get("impact") or ""),
            finding_kind=str(f.get("finding_kind") or ""),
            verification=str(f.get("verification") or ""),
            detail=str(f.get("detail") or ""),
        )

    # Exclude suppressed / invalidated findings from severity totals and executive items
    from report_status import is_suppressed_or_invalidated as _is_suppressed

    def _is_attack_surface(f: Dict[str, Any]) -> bool:
        return str(f.get("assessment_state") or "") == "Attack-surface observation"

    active_vulnerabilities = [
        f for f in vulnerabilities if not _is_suppressed(f) and not _is_attack_surface(f)
    ]
    active_hardening = [
        f for f in hardening_issues if not _is_suppressed(f) and not _is_attack_surface(f)
    ]
    # Attack-surface items are inventoried separately — never in severity totals
    attack_surface_only = [
        f for f in findings_dual if _is_attack_surface(f) and not _is_suppressed(f)
    ]

    # Overall risk ignores hardening noise — only demonstrated vulnerabilities drive Medium+
    vuln_sev = Counter(str(f.get("severity") or "info") for f in active_vulnerabilities)
    hard_sev = Counter(str(f.get("severity") or "info") for f in active_hardening)
    # Do not let unverified / attack-surface high findings drive overall High Risk
    critical = sum(
        1
        for f in active_vulnerabilities
        if str(f.get("severity") or "").lower() == "critical"
        and str(f.get("assessment_state") or "") == "Confirmed vulnerability"
    )
    high = sum(
        1
        for f in active_vulnerabilities
        if str(f.get("severity") or "").lower() == "high"
        and str(f.get("assessment_state") or "") == "Confirmed vulnerability"
    )
    medium = sum(
        1
        for f in active_vulnerabilities
        if str(f.get("severity") or "").lower() == "medium"
        and str(f.get("assessment_state") or "")
        in ("Confirmed vulnerability", "Likely vulnerability")
    )
    low = int(vuln_sev.get("low", 0)) + int(hard_sev.get("low", 0))
    info = int(vuln_sev.get("info", 0)) + int(hard_sev.get("info", 0)) + int(hard_sev.get("medium", 0))

    if critical:
        risk_level = "Critical"
        exec_headline = (
            f"This assessment identified critical vulnerabilities on {host} that should be addressed immediately."
        )
    elif high:
        risk_level = "High"
        exec_headline = (
            f"This assessment identified high-severity vulnerabilities on {host} that deserve prompt remediation."
        )
    elif medium:
        risk_level = "Medium"
        exec_headline = (
            f"This assessment found demonstrated medium-severity vulnerabilities on {host}; "
            "plan fixes in the next cycle."
        )
    elif active_vulnerabilities or active_hardening:
        risk_level = "Low"
        exec_headline = (
            f"No demonstrated medium+ vulnerabilities on {host}. "
            f"Remaining items are hardening / informational / candidates "
            f"({len(active_hardening)} hardening observation(s))."
        )
    else:
        risk_level = "Clear"
        exec_headline = (
            f"No security findings were recorded for {host} in this run. "
            "Treat coverage limits below as part of residual risk."
        )

    # Scan completeness / edge interference overrides risk rating
    scan_status = str(status_meta.get("scan_status") or "")
    inconclusive_reason = str(getattr(stats, "assessment_inconclusive_reason", "") or "")
    coverage_failed = str(getattr(stats, "target_content_coverage", "") or "").lower() == "failed"
    edge_blocked = bool(getattr(stats, "enum_edge_blocked", False))
    if coverage_failed or edge_blocked or "checkpoint" in inconclusive_reason.lower():
        risk_level = "Not assigned"
        reason = inconclusive_reason or (
            "Edge security checkpoint prevented sufficient application and enumeration coverage."
        )
        exec_headline = (
            f"Overall assessment: Inconclusive. Risk rating: Not assigned. "
            f"Reason: {reason} Confirmed vulnerabilities: "
            f"{critical + high + medium}."
        )
    elif scan_status in ("partial", "stopped"):
        incomplete = partial_executive_summary(
            host=host, phase=str(status_meta.get("phase") or "crawl")
        )
        # Completeness is separate from risk — annotate, do not invent High/Critical.
        # Only checkpoint/coverage-failed paths above force Not assigned.
        exec_headline = f"{incomplete} {exec_headline}"

    top_exec = [
        f"{f['id']} [{f['severity'].upper()}] {f['executive']}"
        for f in active_vulnerabilities
        if f["severity"] in ("critical", "high", "medium")
    ][:6]
    if not top_exec and active_vulnerabilities:
        top_exec = [
            f"{f['id']} [{f['severity'].upper()}] {f['executive']}"
            for f in active_vulnerabilities[:4]
        ]
    if not top_exec and active_hardening:
        top_exec = [
            f"Hardening only: {active_hardening[0]['id']} [{active_hardening[0]['severity'].upper()}] "
            f"{active_hardening[0]['title']} — not a demonstrated vulnerability."
        ]
    if not top_exec:
        top_exec = ["No prioritized findings in this run."]

    recommendations = list(conclusion.get("recommendations") or [])
    from report_status import include_in_remediation, is_suppressed_or_invalidated

    roadmap = []
    suppressed_appendix = []
    for f in findings_dual:
        if is_suppressed_or_invalidated(f):
            suppressed_appendix.append(
                {
                    "id": f.get("id"),
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "assessment_state": f.get("assessment_state"),
                    "detail": f.get("detail"),
                    "reason": "Invalidated / false-positive / skipped observation",
                }
            )
    for f in active_vulnerabilities:
        if not include_in_remediation(f):
            continue
        if f["severity"] in ("critical", "high"):
            roadmap.append({"priority": "P1 — Immediate", "item": f"{f['id']}: {f['title']}", "fix": f["fix"]})
        elif f["severity"] == "medium":
            roadmap.append({"priority": "P2 — Next sprint", "item": f"{f['id']}: {f['title']}", "fix": f["fix"]})
        elif f["severity"] == "low":
            roadmap.append({"priority": "P3 — Backlog", "item": f"{f['id']}: {f['title']}", "fix": f["fix"]})
    for f in active_hardening[:8]:
        if not include_in_remediation(f):
            continue
        roadmap.append(
            {
                "priority": "P4 — Hardening backlog",
                "item": f"{f['id']}: {f['title']}",
                "fix": f["fix"],
            }
        )
    roadmap = roadmap[:18]

    protections = list(defense.get("protections_detected") or [])
    limitations = [
        "Findings are based on automated crawling, enumeration, and heuristic checks — not a full manual pentest.",
        "WAF/bot challenges can reduce coverage; absence of a finding is not proof of absence of risk.",
        "Active probes are limited and may not exercise every auth-gated or business-logic path.",
        "Only systems you are authorized to test should be scanned; this report assumes that confirmation was given.",
    ]
    if float(defense.get("gap_rate_percent") or 0) > 40:
        limitations.append(
            "A large share of requests completed without challenge signals — bot/WAF catch rate may be incomplete."
        )
    if int(snap.get("enum_words_total") or 0) and int(snap.get("enum_words_tested") or 0) < int(
        snap.get("enum_words_total") or 0
    ) * 0.2:
        limitations.append("Directory enumeration did not substantially complete the configured wordlist.")
    if status_meta.get("directory_enum_message") and not status_meta.get("directory_enum_started"):
        limitations.append(str(status_meta["directory_enum_message"]))
    if status_meta.get("scan_status") == "partial":
        limitations.append(
            "This report was exported while the scan was still running — treat metrics and findings as partial."
        )

    methodology = [
        "Reconnaissance and optional historical URL seeding (where enabled).",
        "Authenticated or unauthenticated crawl of in-scope links within configured depth/concurrency.",
        "Directory and path enumeration using configured wordlists and/or mutations.",
        "API recon: passive route mining, OpenAPI/Swagger docs, optional light active probes and GraphQL introspection.",
        "Security heuristics (headers, sensitive paths, common vulnerability probes where enabled).",
        "Optional defense/WAF fingerprinting and catch-rate observation during the run.",
        "Grouped findings with plain-language and technical explanations for remediation.",
    ]

    # Build structured finding sections for clear separation in reports
    confirmed_vulns = [
        f for f in active_vulnerabilities
        if str(f.get("assessment_state") or "") == "Confirmed vulnerability"
    ]
    unverified_candidates = [
        f for f in active_vulnerabilities
        if str(f.get("assessment_state") or "") in (
            "Likely vulnerability", "Needs manual validation"
        )
    ]
    passive_observations = [
        f for f in active_vulnerabilities + active_hardening
        if str(f.get("assessment_state") or "") == "Informational technology finding"
    ]
    attack_surface_inventory = list(attack_surface_only)
    # Coverage gaps section: note what phases did/didn't run
    active_probe_coverage = dict(getattr(stats, "active_probe_coverage", None) or {})
    content_coverage = str(getattr(stats, "target_content_coverage", "") or "").lower()
    coverage_gaps: List[str] = []
    if content_coverage == "crawl_only":
        coverage_gaps.append(
            "Coverage is crawl-only: passive heuristics applied but no active injection probes "
            "were run. 'target_content_coverage=crawl_only' does NOT mean a comprehensive security "
            "assessment was performed."
        )
    elif content_coverage == "failed":
        coverage_gaps.append(
            "Crawl coverage failed — edge security checkpoint prevented sufficient application access."
        )
    if not active_probe_coverage:
        coverage_gaps.append(
            "Active security probes (injection, XSS, CSRF canary) did not run or produced no data."
        )
    ts = getattr(stats, "target_selection_coverage", None) or snap.get("target_selection_coverage")
    if isinstance(ts, dict) and ts.get("status") == "insufficient":
        missing = ", ".join(ts.get("missing_families") or []) or "dedicated fixtures"
        coverage_gaps.append(
            f"Target-selection coverage insufficient ({missing}): dedicated fixtures were "
            "discovered but not scheduled for the matching probe family."
        )
    elif str(snap.get("target_selection_coverage") or "") == "insufficient":
        coverage_gaps.append(
            "Target-selection coverage insufficient — dedicated fixtures discovered but not tested."
        )
    av = str(
        getattr(stats, "active_validation_coverage", "")
        or snap.get("active_validation_coverage")
        or ""
    )
    if av in ("partial", "insufficient"):
        coverage_gaps.append(
            "Active vulnerability validation is partial — not all applicable probe families "
            "reached their intended targets."
        )
    if str(snap.get("assessment_status") or getattr(stats, "assessment_status", "") or "") in (
        "incomplete",
        "inconclusive",
    ):
        coverage_gaps.append(
            "Overall vulnerability assessment is incomplete — crawl/enum completion does not "
            "imply full active-probe coverage."
        )
    if not int(snap.get("enum_http_attempts") or 0):
        coverage_gaps.append("Directory/path enumeration did not run — hidden endpoint coverage is absent.")
    if not int(snap.get("subdomain_probes_done") or 0):
        coverage_gaps.append("Subdomain enumeration did not run.")
    if not int(snap.get("api_recon_probes_done") or 0):
        coverage_gaps.append("Active API recon probes did not run.")

    split_coverage = {
        "crawl": str(snap.get("crawl_coverage") or ""),
        "enum": str(snap.get("enum_coverage") or ""),
        "api": str(snap.get("api_coverage") or ""),
        "target_selection": (
            (ts.get("status") if isinstance(ts, dict) else ts) or snap.get("target_selection_coverage") or ""
        ),
        "active_validation": av,
        "vulnerability_assessment": str(
            snap.get("vulnerability_assessment_coverage")
            or snap.get("assessment_status")
            or ""
        ),
    }

    return {
        "product": "VantaCrawl",
        "document_title": "Security Assessment Report",
        "job_title": job_title or f"Assessment — {host}",
        "start_url": start_url,
        "host": host,
        "mode": mode or str(meta.get("mode") or meta.get("profile") or "full"),
        "generated_at": format_dual(),
        "generated_at_note": "Primary clock is IST (India Standard Time); UTC shown in parentheses.",
        "risk_level": risk_level,
        "exec_headline": exec_headline,
        "verdict_title": conclusion.get("verdict_title") or risk_level,
        "verdict_body": conclusion.get("verdict_body") or exec_headline,
        "top_executive_points": top_exec,
        "severity_counts": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
        },
        "finding_sections": {
            "confirmed_vulnerabilities": confirmed_vulns,
            "unverified_candidates": unverified_candidates,
            "passive_observations": passive_observations,
            "attack_surface_inventory": attack_surface_inventory,
            "suppressed_false_positives": suppressed_appendix[:40],
            "coverage_gaps": coverage_gaps,
        },
        "split_coverage": split_coverage,
        "metrics": {
            "pages_crawled": int(snap.get("pages_crawled") or 0),
            "enum_hits": int(snap.get("enum_hits") or getattr(stats, "enum_hits", 0) or 0),
            "api_endpoints": len(getattr(stats, "api_endpoints", []) or []),
            "findings": len(getattr(stats, "findings", []) or []),
            "errors": int(snap.get("errors") or 0),
            "elapsed_seconds": float(snap.get("elapsed_seconds") or 0),
            "enum_words_tested": int(snap.get("enum_words_tested") or 0),
            "enum_words_total": int(snap.get("enum_words_total") or 0),
            "enum_base_words_loaded": int(snap.get("enum_base_words_loaded") or getattr(stats, "enum_base_words_loaded", 0) or 0),
            "enum_base_words_processed": int(snap.get("enum_base_words_processed") or getattr(stats, "enum_base_words_processed", 0) or 0),
            "enum_http_attempts": int(snap.get("enum_http_attempts") or getattr(stats, "enum_http_attempts", 0) or 0),
            "enum_rate_limited": int(snap.get("enum_rate_limited") or getattr(stats, "enum_rate_limited", 0) or 0),
            "enum_rejected_wildcard": int(snap.get("enum_rejected_wildcard") or getattr(stats, "enum_rejected_wildcard", 0) or 0),
            "enum_requested_depth": int(snap.get("enum_requested_depth") or getattr(stats, "enum_requested_depth", 0) or 0),
            "enum_effective_depth": int(snap.get("enum_effective_depth") or getattr(stats, "enum_effective_depth", 0) or 0),
            "enum_depth_reason": str(snap.get("enum_depth_reason") or getattr(stats, "enum_depth_reason", "") or ""),
            "discovered_url_count": int(snap.get("discovered_url_count") or len(getattr(stats, "discovered_urls", []) or [])),
            "queue_size": int(snap.get("queue_size") or getattr(stats, "queue_size", 0) or 0),
            "completion_percent": float(status_meta.get("completion_percent") or 0),
        },
        "enum_validation_conclusion": str(
            snap.get("enum_validation_conclusion")
            or getattr(stats, "enum_validation_conclusion", "")
            or ""
        ),
        "scan_status": status_meta.get("scan_status"),
        "scan_status_meta": status_meta,
        "directory_enum_message": status_meta.get("directory_enum_message"),
        "methodology": methodology,
        # Executive / severity-facing lists exclude suppressed + attack-surface inventory
        "findings": active_vulnerabilities + active_hardening,
        "vulnerabilities": active_vulnerabilities,
        "hardening_issues": active_hardening,
        "recommendations": recommendations,
        "roadmap": roadmap,
        "suppressed_observations": suppressed_appendix[:40],
        "protections": protections,
        "defense": defense,
        "block_journal": list(defense.get("block_journal") or [])[:30],
        "block_status_counts": dict(defense.get("block_status_counts") or {}),
        "block_events_forensic": list(defense.get("block_events_forensic") or [])[:40],
        "enum_hits": list(getattr(stats, "enum_hit_urls", []) or model.get("enum_hits") or [])[:80],
        "limitations": limitations,
        "scan_setup": conclusion.get("scan_setup") or model.get("scan_setup") or {},
        "authorization_note": (
            "This report is intended for authorized security testing only. "
            "Recipients should confirm legal authorization before acting on any technical detail."
        ),
    }

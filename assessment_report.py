"""Professional dual-audience assessment report model (client + security engineer)."""

from __future__ import annotations

import time
from collections import Counter
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from crawl_stats import CrawlStats
from finding_explain import group_findings_for_report
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

    # Overall risk ignores hardening noise — only demonstrated vulnerabilities drive Medium+
    vuln_sev = Counter(str(f.get("severity") or "info") for f in vulnerabilities)
    hard_sev = Counter(str(f.get("severity") or "info") for f in hardening_issues)
    # Do not let unverified / attack-surface high findings drive overall High Risk
    critical = sum(
        1
        for f in vulnerabilities
        if str(f.get("severity") or "").lower() == "critical"
        and str(f.get("assessment_state") or "") == "Confirmed vulnerability"
    )
    high = sum(
        1
        for f in vulnerabilities
        if str(f.get("severity") or "").lower() == "high"
        and str(f.get("assessment_state") or "") == "Confirmed vulnerability"
    )
    medium = sum(
        1
        for f in vulnerabilities
        if str(f.get("severity") or "").lower() == "medium"
        and str(f.get("assessment_state") or "")
        in ("Confirmed vulnerability", "Likely vulnerability")
    )
    low = int(vuln_sev.get("low", 0)) + int(hard_sev.get("low", 0))
    info = int(vuln_sev.get("info", 0)) + int(hard_sev.get("info", 0)) + int(hard_sev.get("medium", 0))

    if status_meta.get("scan_status") == "partial":
        risk_level = "Partial"
        exec_headline = partial_executive_summary(
            host=host, phase=str(status_meta.get("phase") or "crawl")
        )
    elif critical:
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
    elif vulnerabilities or hardening_issues:
        risk_level = "Low"
        exec_headline = (
            f"No demonstrated medium+ vulnerabilities on {host}. "
            f"Remaining items are hardening / informational / candidates "
            f"({len(hardening_issues)} hardening observation(s))."
        )
    else:
        risk_level = "Clear"
        exec_headline = (
            f"No security findings were recorded for {host} in this run. "
            "Treat coverage limits below as part of residual risk."
        )

    top_exec = [
        f"{f['id']} [{f['severity'].upper()}] {f['executive']}"
        for f in vulnerabilities
        if f["severity"] in ("critical", "high", "medium")
    ][:6]
    if not top_exec and vulnerabilities:
        top_exec = [
            f"{f['id']} [{f['severity'].upper()}] {f['executive']}" for f in vulnerabilities[:4]
        ]
    if not top_exec and hardening_issues:
        top_exec = [
            f"Hardening only: {hardening_issues[0]['id']} [{hardening_issues[0]['severity'].upper()}] "
            f"{hardening_issues[0]['title']} — not a demonstrated vulnerability."
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
    for f in vulnerabilities:
        if not include_in_remediation(f):
            continue
        if f["severity"] in ("critical", "high"):
            roadmap.append({"priority": "P1 — Immediate", "item": f"{f['id']}: {f['title']}", "fix": f["fix"]})
        elif f["severity"] == "medium":
            roadmap.append({"priority": "P2 — Next sprint", "item": f"{f['id']}: {f['title']}", "fix": f["fix"]})
        elif f["severity"] == "low":
            roadmap.append({"priority": "P3 — Backlog", "item": f"{f['id']}: {f['title']}", "fix": f["fix"]})
    for f in hardening_issues[:8]:
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

    return {
        "product": "VantaCrawl",
        "document_title": "Security Assessment Report",
        "job_title": job_title or f"Assessment — {host}",
        "start_url": start_url,
        "host": host,
        "mode": mode or str(meta.get("mode") or meta.get("profile") or "full"),
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
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
        "metrics": {
            "pages_crawled": int(snap.get("pages_crawled") or 0),
            "enum_hits": int(snap.get("enum_hits") or getattr(stats, "enum_hits", 0) or 0),
            "api_endpoints": len(getattr(stats, "api_endpoints", []) or []),
            "findings": len(getattr(stats, "findings", []) or []),
            "errors": int(snap.get("errors") or 0),
            "elapsed_seconds": float(snap.get("elapsed_seconds") or 0),
            "enum_words_tested": int(snap.get("enum_words_tested") or 0),
            "enum_words_total": int(snap.get("enum_words_total") or 0),
            "discovered_url_count": int(snap.get("discovered_url_count") or len(getattr(stats, "discovered_urls", []) or [])),
            "queue_size": int(snap.get("queue_size") or getattr(stats, "queue_size", 0) or 0),
            "completion_percent": float(status_meta.get("completion_percent") or 0),
        },
        "scan_status": status_meta.get("scan_status"),
        "scan_status_meta": status_meta,
        "directory_enum_message": status_meta.get("directory_enum_message"),
        "methodology": methodology,
        "findings": findings_dual,
        "vulnerabilities": vulnerabilities,
        "hardening_issues": hardening_issues,
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

"""Screenshot audit: enum abort integrity, risk, cloud FP, params, export honesty."""

from __future__ import annotations

import json
import time

from assessment_report import build_assessment_document
from checkpoint import load_enum_checkpoint, save_enum_checkpoint
from cloud_enum import _bucket_related_to_target
from crawl_stats import CrawlStats
from defense_verify import DefenseTracker
from detailed_report import _takeaways
from enum_validation import (
    CLASS_PROVISIONAL,
    CLASS_REVOKED,
    CLASS_VALIDATION_INTERRUPTED,
)
from reporting import ReportWriter
from search_report import build_search_conclusion
from security_scan import discover_parameters


def test_bucket_related_requires_target_correlation():
    assert _bucket_related_to_target("acme-prod-assets", "acme.example.com") is True
    assert _bucket_related_to_target("random-public-bucket", "acme.example.com") is False
    assert _bucket_related_to_target("backup", "acme.example.com") is False


def test_discover_parameters_skips_meta_viewport_description():
    html = """
    <html><head>
      <meta name="viewport" content="width=device-width">
      <meta name="description" content="Site">
      <meta name="theme-color" content="#000">
    </head><body>
      <form action="/search"><input name="q" /><input name="page" /></form>
    </body></html>
    """
    params = discover_parameters(
        "https://example.com/x",
        html,
        forms=[{"action": "https://example.com/search", "fields": ["q", "page"]}],
    )
    names = {p["name"] for p in params}
    assert "viewport" not in names
    assert "description" not in names
    assert "theme-color" not in names
    assert "q" in names
    assert "page" in names


def test_enum_checkpoint_abort_honesty_fields(tmp_path):
    path = str(tmp_path / "enum.json")
    save_enum_checkpoint(
        path,
        "https://example.com/",
        9,
        [],
        0,
        ["https://example.com/login"],
        enumeration_state="aborted_edge_checkpoint",
        remaining_base_words=2930,
        resume_allowed=True,
    )
    state = load_enum_checkpoint(path)
    assert state["word_index"] == 9
    assert state["last_attempted_word_index"] == 9
    assert state["enumeration_state"] == "aborted_edge_checkpoint"
    assert state["remaining_base_words"] == 2930
    assert state["resume_allowed"] is True


def test_enum_elapsed_freezes_after_mark_finished():
    stats = CrawlStats()
    stats.enum_started_at = time.time() - 80.0
    stats.mark_enum_finished()
    frozen = stats.enum_elapsed_seconds()
    time.sleep(0.05)
    assert abs(stats.enum_elapsed_seconds() - frozen) < 0.02
    assert frozen < 90


def test_edge_blocked_forces_not_assigned_risk():
    stats = CrawlStats()
    stats.enum_edge_blocked = True
    stats.assessment_inconclusive_reason = "edge security checkpoint (vercel_security_checkpoint)"
    stats.record_finding(
        "header_audit",
        "low",
        "https://example.com/",
        "Missing HSTS",
        role="hardening",
    )
    doc = build_assessment_document(stats, "https://example.com/", config_meta={})
    assert doc["risk_level"] == "Not assigned"
    assert "Inconclusive" in doc["exec_headline"]

    conclusion = build_search_conclusion(
        stats,
        "https://example.com/",
        profile="full",
        security_enabled=True,
    )
    assert "INCONCLUSIVE" in conclusion["verdict_title"]
    assert "not assigned" in conclusion["verdict_title"].lower()


def test_json_export_separates_retention_and_export_omission(tmp_path):
    stats = CrawlStats()
    stats.requests_omitted = 42
    for i in range(2105):
        stats.request_ledger.append(
            {"phase": "crawl", "url": f"https://example.com/{i}", "status": 200}
        )
    stats.total_requests_observed = 2200
    stats.requests_retained = 2105
    writer = ReportWriter(str(tmp_path), "https://example.com/")
    path = writer.write_json(stats)
    with open(path, encoding="utf-8") as fh:
        payload = json.load(fh)
    assert payload["requests_omitted"] == 42
    assert payload["requests_omitted_from_json_export"] == 105
    assert payload["requests_exported"] == 2000


def test_defense_posture_is_observational_not_waf_grade():
    tracker = DefenseTracker(start_url="https://example.com/")
    tracker.protections_seen.add("akamai")
    tracker.caught_count = 80
    tracker.unchallenged_count = 20
    title, body = tracker.posture_verdict()
    assert "OBSERVATIONAL" in title
    assert "STRONG" not in title
    assert "PARTIAL" not in title
    assert "protection" in body.lower() or "waf" in body.lower()


def test_scoped_interrupt_vs_revoke_classifications():
    """Distinct provisionals interrupt; checkpoint-cluster anchors revoke."""
    from enum_validation import HitProvenanceTracker, fingerprint_from_response

    tracker = HitProvenanceTracker()
    login_body = (
        b"<!doctype html><html><head><title>Sign in</title></head>"
        b"<body><form>username password</form></body></html>"
    )
    cp_body = (
        b"<!doctype html><html><head><title>Vercel Security Checkpoint</title></head>"
        b"<body>Vercel Security Checkpoint window.vercel challenge</body></html>"
    )

    def _add(url: str, body: bytes, title: str):
        fp = fingerprint_from_response(url=url, status=200, body=body)
        fp.title = title
        return tracker.classify_and_record(
            url=url,
            base_word=url.rsplit("/", 1)[-1],
            variant=url.rsplit("/", 1)[-1],
            requested_status=200,
            final_status=200,
            final_url=url,
            fingerprint=fp,
            wildcard_rejected=False,
            wildcard_similarity=0.0,
            baseline_used="",
            soft_404=False,
            path_shape="plain",
        )

    _add("https://example.com/login", login_body, "Sign in")

    def _cp(n: int) -> bytes:
        return cp_body + f" <!-- {n:016x} -->".encode()

    anchor = _add("https://example.com/administrator.txt", _cp(1), "Vercel Security Checkpoint")
    for i, url in enumerate(
        (
            "https://example.com/class.php",
            "https://example.com/seo.aspx",
            "https://example.com/promotion.bak",
        ),
        start=2,
    ):
        _add(url, _cp(i), "Vercel Security Checkpoint")

    cls, state, reason = tracker.disposition_on_edge_abort("https://example.com/login")
    assert cls == CLASS_VALIDATION_INTERRUPTED
    assert state == "validation_interrupted"
    assert reason == "edge_blocked_before_final_validation"

    cls2, state2, reason2 = tracker.disposition_on_edge_abort(anchor.url)
    assert cls2 == CLASS_REVOKED
    assert state2 == "revoked"
    assert "fallback" in reason2
    assert CLASS_VALIDATION_INTERRUPTED == "validation_interrupted"
    assert "provisional" in CLASS_PROVISIONAL
    assert "revoked" in CLASS_REVOKED


def test_broken_link_takeaway_prefers_404_over_access_denied():
    stats = CrawlStats()
    stats.broken_links = [
        {"url": "https://example.com/a", "status": "403", "class": "access_denied"},
        {"url": "https://example.com/b", "status": "403", "class": "access_denied"},
        {"url": "https://example.com/c", "status": "404", "class": "not_found"},
    ]
    items = _takeaways(stats, finding_groups=[], defense=None)
    joined = " ".join(items)
    assert "broken link" in joined.lower()
    assert "access-denied" in joined.lower() or "404" in joined


def test_snapshot_includes_abort_honesty_fields():
    stats = CrawlStats()
    stats.enum_edge_blocked = True
    stats.enum_state = "aborted_edge_checkpoint"
    stats.enum_coverage_complete = False
    stats.enum_resume_allowed = True
    stats.enum_remaining_base_words = 2900
    stats.edge_circuit_breaker = True
    stats.hsts_observed = True
    snap = stats.snapshot()
    assert snap["enum_state"] == "aborted_edge_checkpoint"
    assert snap["enum_coverage_complete"] is False
    assert snap["enum_resume_allowed"] is True
    assert snap["enum_remaining_base_words"] == 2900
    assert snap["edge_circuit_breaker"] is True
    assert snap["hsts_observed"] is True

"""Scan report accuracy: snapshot restore, finding quality, report status."""

from __future__ import annotations

import asyncio
import base64
import json
import time
from pathlib import Path
from unittest.mock import AsyncMock

from assessment_report import build_assessment_document
from crawl_stats import CrawlStats
from finding_impact import assess_cors, assess_csrf, assess_tier_category
from finding_kind import classify_finding_kind
from report_status import scan_status_from_stats
from reporting import crawl_stats_from_partial, write_findings_snapshot
from security_scan import _should_skip_secret_match, scan_file_upload, scan_secrets
from tier_security import probe_mass_assignment, probe_race_conditions, probe_rate_limit


def _b64(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_snapshot_restores_elapsed_and_discovered(tmp_path: Path):
    stats = CrawlStats()
    stats.started_at = time.time() - 4680  # ~1h18m
    stats.pages_crawled = 1861
    stats.links_found = 3336
    stats.errors = 37
    stats.bytes_downloaded = 12_345_678
    stats.queue_size = 1488
    stats.route_variants_skipped = 52000
    for i in range(200):
        stats.discovered_urls.add(f"https://lab.example/p/{i}")
    path = write_findings_snapshot(tmp_path, stats)
    assert Path(path).is_file()
    snap = json.loads(Path(path).read_text(encoding="utf-8"))
    assert snap["pages_crawled"] == 1861
    assert snap["elapsed_seconds"] >= 4600
    assert snap["discovered_url_count"] == 200
    assert snap["queue_size"] == 1488
    assert snap["scan_status"] == "partial"
    assert snap["report_generated_during_scan"] is True
    assert snap["remaining_jobs"] == 1488

    rebuilt = crawl_stats_from_partial(snapshot=snap, progress={})
    assert rebuilt.pages_crawled == 1861
    assert rebuilt.elapsed_seconds() >= 4500
    assert rebuilt.queue_size == 1488
    assert len(rebuilt.discovered_urls) == 200
    live = rebuilt.snapshot()
    assert live["elapsed_seconds"] >= 4500
    assert live["urls_per_minute"] < 1000  # not millions from 0.1s elapsed
    assert live["scan_status"] == "partial"


def test_enum_not_started_message():
    stats = CrawlStats()
    stats.pages_crawled = 100
    stats.queue_size = 50
    meta = scan_status_from_stats(stats)
    assert meta["scan_status"] == "partial"
    assert "not started" in meta["directory_enum_message"].lower()
    assert "0 hidden paths found" not in meta["directory_enum_message"].lower()


def test_mass_assignment_html_shell_suppressed():
    class Resp:
        status_code = 200
        text = "<!DOCTYPE html><html><body>App shell</body></html>"
        headers = {"content-type": "text/html"}

    client = AsyncMock()
    client.post = AsyncMock(return_value=Resp())
    findings = asyncio.run(
        probe_mass_assignment(client, "https://lab.example/us/en/web/account/history")
    )
    assert findings == []


def test_mass_assignment_json_persist_confirmed():
    class Resp:
        status_code = 200
        text = json.dumps({"ok": True, "isAdmin": True})
        headers = {"content-type": "application/json"}

    client = AsyncMock()
    client.post = AsyncMock(return_value=Resp())
    findings = asyncio.run(
        probe_mass_assignment(client, "https://lab.example/api/v1/users/me")
    )
    assert findings
    assert findings[0][0] == "mass_assignment"
    assert findings[0][1] == "high"
    assert "persisted" in findings[0][2].lower()


def test_mass_assignment_impact_downgrades_inventory():
    result = assess_tier_category(
        "mass_assignment",
        "Privilege/debug parameter names referenced in client code: isAdmin",
        "high",
    )
    assert result.severity == "info"
    assert result.validation == "unverified"


def test_cors_sitemap_akzip_is_info():
    result = assess_cors(
        "CORS reflects arbitrary Origin with credentials",
        "high",
        url="https://lab.example/sitemap.xml",
        cookies=[{"name": "AKZip", "host": "lab.example", "role": "analytics"}],
    )
    assert result.severity == "info"


def test_rate_limit_all_301_is_empty():
    class Resp:
        status_code = 301
        headers = {}

    client = AsyncMock()
    client.get = AsyncMock(return_value=Resp())
    findings = asyncio.run(
        probe_rate_limit(client, "https://lab.example/login", bursts=12)
    )
    assert findings == []


def test_rate_limit_kind_is_hardening_intel():
    assert (
        classify_finding_kind(category="rate_limit", severity="info", detail="candidate")
        == "hardening"
    )


def test_csrf_no_session_summary_consistent():
    result = assess_csrf(
        "State-changing POST form without CSRF token (hardening — no session cookie observed)",
        "info",
    )
    assert "session cookie is present" not in result.summary.lower()
    assert "no session cookie" in result.summary.lower()


def test_race_static_html_skipped():
    class Resp:
        status_code = 200
        text = "<!DOCTYPE html><html>terms</html>"
        headers = {"content-type": "text/html"}

    client = AsyncMock()
    client.post = AsyncMock(return_value=Resp())
    findings = asyncio.run(
        probe_race_conditions(
            client, "https://lab.example/us/en/wallet/terms-and-conditions.html"
        )
    )
    assert findings == []


def test_openai_hyphenated_fp_skipped():
    assert _should_skip_secret_match(
        label="OpenAI API Key",
        raw="sk-karlek-och-faktisk-forlustabcdef",
        body_text='x="sk-karlek-och-faktisk-forlustabcdef"',
        start=3,
        end=40,
        value="sk-karlek-och-faktisk-forlustabcdef",
    )


def test_forgot_password_route_never_password():
    assert _should_skip_secret_match(
        label="Hardcoded Password",
        raw='password="/forgot-password/reset-password"',
        body_text='password="/forgot-password/reset-password"',
        start=0,
        end=40,
        value="/forgot-password/reset-password",
    )
    body = 'const x = { password: "/user/forgot-password" };'
    findings = scan_secrets(body, "https://lab.example/a.js")
    assert not any("password" in (f[0] or "").lower() and "forgot" in (f[2] or "").lower() for f in findings)


def test_file_upload_is_surface_info():
    forms = [
        {
            "action": "/global/en/rmo-form.html",
            "method": "POST",
            "file_fields": ["attachment"],
            "accept": "",
        }
    ]
    findings = scan_file_upload(forms, "https://lab.example/global/en/rmo-form.html")
    assert findings
    assert findings[0][1] == "info"
    assert "server-side validation not assessed" in findings[0][2].lower()
    assert classify_finding_kind(category="file_upload", severity="info") == "hardening"


def test_partial_assessment_not_high_risk_from_unverified_mass_assignment():
    stats = CrawlStats()
    stats.pages_crawled = 50
    stats.queue_size = 100
    stats.findings = [
        {
            "severity": "high",
            "category": "mass_assignment",
            "detail": "Privilege/debug parameter names referenced in client code: isAdmin",
            "url": "https://lab.example/app.js",
            "validation": "unverified",
            "impact": "informational",
            "finding_kind": "vulnerability",
        }
    ]
    doc = build_assessment_document(stats, "https://lab.example/")
    assert doc["risk_level"] in ("Partial", "Low", "Clear")
    assert doc["risk_level"] != "High"
    assert doc["scan_status"] == "partial"
    assert "candidate" in doc["exec_headline"].lower() or "partial" in doc["exec_headline"].lower() or "validation" in doc["exec_headline"].lower()


def test_expired_jwt_skipped_as_secret():
    token = (
        f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}."
        f"{_b64({'sub': '1', 'exp': 1717200000})}."  # June 2024-ish
        "signaturepad1234567890abcdef"
    )
    assert _should_skip_secret_match(
        label="Named Credential",
        raw=f'lisa_access_token="{token}"',
        body_text=f'lisa_access_token="{token}"',
        start=0,
        end=20,
        value=token,
    )

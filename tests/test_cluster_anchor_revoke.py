"""First-response poisoning / content-equivalent cluster-anchor revoke."""

from __future__ import annotations

from pathlib import Path

from crawl_stats import CrawlStats
from enum_validation import (
    CLASS_CONTENT_DUP,
    CLASS_PROVISIONAL,
    CLASS_REVOKED,
    HitProvenanceTracker,
    fingerprint_from_response,
)
from reporting import crawl_stats_from_partial, load_findings_snapshot, write_findings_snapshot


CHECKPOINT_BODY = (
    b"<!doctype html><html><head><title>Vercel Security Checkpoint</title></head>"
    b"<body>Vercel Security Checkpoint window.vercel challenge</body></html>"
)


def _rec(tracker: HitProvenanceTracker, url: str, body: bytes = CHECKPOINT_BODY):
    fp = fingerprint_from_response(url=url, status=200, body=body)
    # Force a distinctive title for checkpoint detection in cluster logic
    fp.title = "Vercel Security Checkpoint"
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


def test_first_response_is_provisional_not_validated():
    tracker = HitProvenanceTracker()
    rec = _rec(tracker, "https://example.com/administrator.txt")
    assert rec.classification == CLASS_PROVISIONAL
    assert not rec.validated
    assert rec.state == "provisional"


def test_cluster_anchor_revoked_when_unrelated_paths_converge():
    tracker = HitProvenanceTracker()
    # Slightly different bodies (dynamic nonce) but same normalized hash after scrubbing
    def _body(n: int) -> bytes:
        return CHECKPOINT_BODY + f" <!-- {n:016x} -->".encode()

    r1 = _rec(tracker, "https://example.com/administrator.txt", _body(1))
    assert r1.classification == CLASS_PROVISIONAL
    assert not r1.validated

    paths = [
        "https://example.com/class.php",
        "https://example.com/seo.aspx",
        "https://example.com/promotion.bak",
    ]
    for i, url in enumerate(paths):
        rec = _rec(tracker, url, _body(i + 2))
        assert rec.classification == CLASS_CONTENT_DUP
        assert not rec.validated
        assert "administrator.txt" in rec.acceptance_reason

    # Anchor must be revoked — never left as a validated/hidden hit
    assert "https://example.com/administrator.txt" in tracker.revoked_urls
    events = tracker.drain_revokes()
    assert events
    assert events[0].url.endswith("/administrator.txt")
    assert events[0].reason == "anchor_of_content_equivalent_fallback_cluster"
    assert events[0].cluster_size >= 2

    # Promote must not resurrect the revoked anchor
    promoted = tracker.promote_survivors()
    assert not any(p.url.endswith("/administrator.txt") for p in promoted)
    for rec in tracker.records:
        if rec.url.endswith("/administrator.txt"):
            assert rec.classification == CLASS_REVOKED
            assert not rec.validated


def test_fallback_cluster_revokes_without_checkpoint_title():
    """Generic soft-fallback: ≥3 unrelated paths + multiple extensions ⇒ revoke."""
    tracker = HitProvenanceTracker()
    body = b"<html><title>Not Found</title><body>soft fallback page shared</body></html>"

    def add(url: str):
        fp = fingerprint_from_response(url=url, status=200, body=body)
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

    assert add("https://example.com/administrator.txt").classification == CLASS_PROVISIONAL
    assert add("https://example.com/class.php").classification == CLASS_CONTENT_DUP
    assert add("https://example.com/seo.aspx").classification == CLASS_CONTENT_DUP
    # Third unrelated + second/third extension tips revoke threshold
    third = add("https://example.com/promotion.bak")
    assert third.classification == CLASS_CONTENT_DUP
    assert "https://example.com/administrator.txt" in tracker.revoked_urls
    events = tracker.drain_revokes()
    assert events and events[0].cluster_size >= 3


def test_unique_provisional_promotes_to_confirmed():
    tracker = HitProvenanceTracker()
    body = b"<html><title>Real Admin</title><body>unique admin panel xyz</body></html>"
    fp = fingerprint_from_response(url="https://example.com/secret-admin", status=200, body=body)
    rec = tracker.classify_and_record(
        url="https://example.com/secret-admin",
        base_word="secret-admin",
        variant="secret-admin",
        requested_status=200,
        final_status=200,
        final_url="https://example.com/secret-admin",
        fingerprint=fp,
        wildcard_rejected=False,
        wildcard_similarity=0.0,
        baseline_used="",
        soft_404=False,
        path_shape="plain",
    )
    assert rec.classification == CLASS_PROVISIONAL
    promoted = tracker.promote_survivors()
    assert len(promoted) == 1
    assert promoted[0].validated
    assert promoted[0].classification == "confirmed_unique_resource"


def test_stop_snapshot_preserves_enum_and_ledger_counters(tmp_path: Path):
    stats = CrawlStats()
    stats.pages_crawled = 3
    stats.enum_http_attempts = 130
    stats.enum_words_tested = 2151
    stats.enum_words_total = 2939
    stats.enum_rejected_wildcard = 0
    stats.enum_content_equivalent_rejects = 130  # type: ignore[attr-defined]
    stats.enum_started_at = 1_700_000_000.0
    stats.request_ledger = [{"url": f"https://x/{i}"} for i in range(50)]
    stats.total_requests_observed = 8000
    stats.forms = [{"action": "/login", "method": "POST"}]
    stats.js_route_urls = ["/app", "/dash"]
    stats.broken_links = [{"url": "https://x/missing", "status": 404}]
    stats.effective_config_meta = {  # type: ignore[attr-defined]
        "use_wordlist": True,
        "enum_words_loaded": 2939,
        "crawl_concurrency": 4,
        "enum_concurrency": 35,
        "wordlist_file": "/tmp/words.txt",
    }
    stats.enum_hit_records = [  # type: ignore[attr-defined]
        {
            "url": "https://x/administrator.txt",
            "validated": False,
            "classification": CLASS_REVOKED,
            "state": "revoked",
        }
    ]

    path = write_findings_snapshot(tmp_path, stats)
    assert Path(path).is_file()
    snap = load_findings_snapshot(tmp_path)
    assert snap is not None
    assert snap["enum_http_attempts"] == 130
    assert snap["enum_words_tested"] == 2151
    assert snap["enum_started_at"] == 1_700_000_000.0
    assert snap["request_ledger_count"] == 50
    assert snap["total_requests_observed"] == 8000
    assert snap["form_count"] == 1
    assert snap["js_route_count"] == 2
    assert snap["effective_config_meta"]["use_wordlist"] is True

    # Simulate a poorer overwrite attempt — richer prior must win
    empty = CrawlStats()
    write_findings_snapshot(tmp_path, empty)
    snap2 = load_findings_snapshot(tmp_path)
    assert snap2["enum_http_attempts"] == 130
    assert snap2["request_ledger_count"] == 50

    rebuilt = crawl_stats_from_partial(snapshot=snap2, progress={})
    assert rebuilt.enum_http_attempts == 130
    assert rebuilt.enum_words_tested == 2151
    assert rebuilt.enum_started_at == 1_700_000_000.0
    assert len(rebuilt.forms) == 1
    assert len(rebuilt.js_route_urls) == 2

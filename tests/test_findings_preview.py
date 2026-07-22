"""Live findings preview: mask + reveal + cookie collapse."""

from __future__ import annotations

from findings_preview import build_findings_preview


def test_cookie_preview_masks_and_keeps_full_for_reveal():
    full = "9810abcdef0123456789abcdef8199"
    rows = build_findings_preview(
        [
            {
                "category": "authentication",
                "severity": "low",
                "url": "https://westernunion.com/sitemap.xml",
                "detail": (
                    "Cookie `AKZip` — unclassified but looks like an opaque token. "
                    "Impact: possible_credential."
                ),
                "evidence": full,
                "impact": "possible_credential",
                "validation": "unverified",
            }
        ]
    )
    assert len(rows) == 1
    assert rows[0]["evidence_full"] == full
    assert "…" in rows[0]["evidence_masked"]
    assert rows[0]["evidence_masked"] != full
    assert rows[0]["impact"] == "possible_credential"


def test_preview_collapses_duplicate_cookie_rows():
    detail = (
        "Cookie `AKZip` — unclassified but looks like an opaque token. "
        "Impact: possible_credential."
    )
    full = "9810abcdef0123456789abcdef8199"
    rows = build_findings_preview(
        [
            {
                "category": "authentication",
                "severity": "low",
                "url": "https://westernunion.com/sitemap.xml",
                "detail": detail,
                "evidence": full,
                "impact": "possible_credential",
            },
            {
                "category": "authentication",
                "severity": "low",
                "url": "https://westernunion.com/sitemap.xml",
                "detail": detail,
                "evidence": full,
                "impact": "possible_credential",
            },
            {
                "category": "authentication",
                "severity": "low",
                "url": "https://www.westernunion.com/us/en",
                "detail": detail,
                "evidence": full,
                "impact": "possible_credential",
            },
        ]
    )
    assert len(rows) == 1


def test_premasked_evidence_does_not_fake_reveal():
    rows = build_findings_preview(
        [
            {
                "category": "authentication",
                "severity": "low",
                "url": "https://westernunion.com/",
                "detail": "Cookie `AKZip` — opaque. Impact: possible_credential.",
                "evidence": "9810…8199",
                "impact": "possible_credential",
            }
        ]
    )
    assert rows[0]["evidence_masked"] == "9810…8199"
    assert rows[0]["evidence_full"] == ""

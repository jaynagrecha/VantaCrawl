"""Option C recon extractors — high accuracy, low volume."""

from recon_active import well_known_is_real
from recon_extract import (
    extract_cloud_urls,
    extract_dom_sinks,
    extract_emails,
    extract_interesting_comments,
    extract_internal_hosts,
    extract_link_rels,
    extract_third_party_scripts,
    inventory_security_headers,
    parse_sitemap_locs,
)


def test_email_filters_noise():
    text = "Contact us at security@acme.example and noreply@example.com plus user@w3.org"
    emails = extract_emails(text)
    assert "security@acme.example" in emails
    assert "noreply@example.com" not in emails
    assert "user@w3.org" not in emails


def test_internal_hosts_only():
    text = 'fetch("https://staging.acme.internal/api"); img src="https://cdn.example.com/a.js"'
    hosts = extract_internal_hosts(text, page_host="www.acme.com")
    assert "staging.acme.internal" in hosts
    assert "cdn.example.com" not in hosts


def test_third_party_known_vendor():
    html = '<script src="https://www.googletagmanager.com/gtm.js"></script>'
    rows = extract_third_party_scripts(html, page_host="shop.example")
    assert rows and rows[0]["vendor"] == "Google Tag Manager"


def test_link_rel_interesting_only():
    html = """
    <link rel="canonical" href="/page">
    <link rel="stylesheet" href="/style.css">
    <link rel="manifest" href="/manifest.json">
    """
    rows = extract_link_rels(html, "https://x.com/")
    rels = {r["rel"] for r in rows}
    assert "canonical" in rels and "manifest" in rels
    assert "stylesheet" not in rels


def test_comments_require_urlish():
    text = "<!-- just a layout note --> <!-- TODO: remove /admin/debug before prod -->"
    hits = extract_interesting_comments(text)
    assert len(hits) == 1
    assert "/admin/debug" in hits[0]


def test_dom_sink_needs_user_input_nearby():
    safe = "el.innerHTML = '<b>static</b>';"
    risky = "el.innerHTML = location.hash;"
    assert extract_dom_sinks(safe) == []
    assert extract_dom_sinks(risky)


def test_cloud_urls():
    text = 'const db = "https://myapp.firebaseio.com/items";'
    assert any("firebaseio.com" in u for u in extract_cloud_urls(text))


def test_security_header_inventory():
    inv = inventory_security_headers(
        {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "Server": "nginx",
        }
    )
    assert "content-security-policy" in inv
    assert "server" not in inv


def test_sitemap_index_vs_urlset():
    index = """<?xml version="1.0"?>
    <sitemapindex><sitemap><loc>https://x.com/sitemap-posts.xml</loc></sitemap></sitemapindex>"""
    pages, children = parse_sitemap_locs(index)
    assert pages == []
    assert "https://x.com/sitemap-posts.xml" in children

    urlset = """<?xml version="1.0"?>
    <urlset><url><loc>https://x.com/a</loc></url><url><loc>https://x.com/b</loc></url></urlset>"""
    pages, children = parse_sitemap_locs(urlset)
    assert "https://x.com/a" in pages
    assert children == []


def test_well_known_html_soft404_rejected():
    assert (
        well_known_is_real(
            200,
            "<!DOCTYPE html><html><body>Not Found</body></html>",
            "text/html",
        )
        is None
    )


def test_well_known_oidc_json_accepted():
    body = '{"issuer":"https://x.com","authorization_endpoint":"https://x.com/auth"}'
    proof = well_known_is_real(200, body, "application/json")
    assert proof and "Confirmed" in proof

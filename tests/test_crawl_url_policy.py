"""Mapper-quality policy: non-HTTP, query caps, static assets, forms, scope."""

from crawl_stats import CrawlStats
from crawl_url_policy import (
    QueryVariantTracker,
    form_fingerprint,
    has_invalid_percent_encoding,
    host_in_exact_origin_scope,
    is_html_crawl_candidate,
    is_static_asset_url,
    resolve_http_target,
    strip_tracking_params,
)
from crawler_common import enqueue_discovered_url, normalize_raw_url
from security_scan import extract_forms


def test_resolve_rejects_javascript_and_mailto():
    assert resolve_http_target("javascript:void(0);", "https://ex.com/") is None
    assert resolve_http_target("mailto:a@b.com", "https://ex.com/") is None
    assert resolve_http_target("#anchor", "https://ex.com/") is None
    assert resolve_http_target("/ok", "https://ex.com/a/") == "https://ex.com/ok"


def test_normalize_raw_url_rejects_non_http():
    assert normalize_raw_url("javascript:void(0)", "https://ex.com/") is None
    assert normalize_raw_url("about:blank", "https://ex.com/") is None
    out = normalize_raw_url("../b", "https://ex.com/a/")
    assert out and out.startswith("https://ex.com/")


def test_invalid_percent_encoding():
    bad = "https://ex.com/?pid=Argentina%201%20Web%201%Peru%20app"
    assert has_invalid_percent_encoding(bad)
    assert resolve_http_target(bad, "") is None


def test_query_variant_cap_sendamount():
    tracker = QueryVariantTracker(max_values_per_parameter=2, max_query_variants_per_endpoint=3)
    base = "https://www.example.com/currency-converter/ars-to-pen-rate.html"
    assert tracker.allow(f"{base}?sendAmount=5000")
    assert tracker.allow(f"{base}?sendAmount=150000")
    assert not tracker.allow(f"{base}?sendAmount=75000")
    assert tracker.skipped_variants >= 1


def test_tracking_params_stripped_from_identity():
    url = "https://ex.com/p?utm_source=x&id=1"
    cleaned = strip_tracking_params(url)
    assert "utm_source" not in cleaned
    assert "id=1" in cleaned


def test_static_assets_not_html_candidates():
    assert is_static_asset_url("https://ex.com/staticassets/css/ar/es/app.css")
    assert not is_html_crawl_candidate("https://ex.com/staticassets/css/ar/es/app.css")
    assert is_html_crawl_candidate("https://ex.com/send-money.html")
    # JS stays enqueueable for extractors — capability preserved
    from crawl_url_policy import is_analysis_asset_url, is_page_data_json_url

    assert is_analysis_asset_url("https://ex.com/static/app.js")
    assert is_html_crawl_candidate("https://ex.com/static/app.js")
    # page-data.json: inventoried, not HTML/browser queue
    assert is_page_data_json_url("https://ex.com/staticassets/page-data/be/en/x/page-data.json")
    assert not is_html_crawl_candidate("https://ex.com/staticassets/page-data/be/en/x/page-data.json")
    assert not is_analysis_asset_url("https://ex.com/staticassets/page-data/be/en/x/page-data.json")


def test_route_template_sampling_preserves_inventory():
    from crawl_url_policy import RouteTemplateTracker, route_template_key

    key = route_template_key(
        "https://www.westernunion.com/be/en/send-money-to-oman.html"
    )
    assert "{locale}" in key
    assert "{destination}" in key
    assert route_template_key(
        "https://www.westernunion.com/be/fr/send-money-to-panama.html"
    ) == key

    tracker = RouteTemplateTracker(
        max_instances_per_route_template=3,
        max_locales_per_route_template=2,
        same_locale_only=True,
        start_url="https://www.westernunion.com/be/en/home.html",
    )
    assert tracker.allow("https://www.westernunion.com/be/en/send-money-to-oman.html")
    assert tracker.allow("https://www.westernunion.com/be/en/send-money-to-panama.html")
    assert tracker.allow("https://www.westernunion.com/be/en/send-money-to-peru.html")
    assert not tracker.allow("https://www.westernunion.com/be/en/send-money-to-chile.html")
    # Other locale inventoried but not queued when same_locale_only
    assert not tracker.allow("https://www.westernunion.com/be/fr/send-money-to-oman.html")
    assert tracker.inventory_counts()[key] >= 5


def test_query_cap_preserves_inventory():
    tracker = QueryVariantTracker(max_values_per_parameter=2, max_query_variants_per_endpoint=3)
    base = "https://www.example.com/currency-converter/ars-to-pen-rate.html"
    assert tracker.allow(f"{base}?sendAmount=5000")
    assert tracker.allow(f"{base}?sendAmount=150000")
    assert not tracker.allow(f"{base}?sendAmount=75000")
    rows = tracker.inventory_rows()
    send = [r for r in rows if r["name"] == "sendamount"]
    assert send and send[0]["values_count"] == 3
    assert set(send[0]["values_sample"]) == {"5000", "150000", "75000"}


def test_enqueue_still_fetches_js_when_skipping_css():
    discovered = set()
    queue = []
    stats = CrawlStats()
    assert not enqueue_discovered_url(
        "https://ex.com/staticassets/css/x.css",
        discovered,
        queue,
        "out.txt",
        lambda *_: None,
        stats=stats,
        skip_static_pages=True,
        start_url="https://ex.com/",
    )
    assert enqueue_discovered_url(
        "https://ex.com/static/app.bundle.js",
        discovered,
        queue,
        "out.txt",
        lambda *_: None,
        stats=stats,
        skip_static_pages=True,
        start_url="https://ex.com/",
    )
    assert any(u.endswith(".js") for u in queue)


def test_enqueue_skips_static_and_caps_query():
    discovered = set()
    queue = []
    log = []
    stats = CrawlStats()
    tracker = QueryVariantTracker(max_values_per_parameter=2, max_query_variants_per_endpoint=3)
    base = "https://ex.com/rate.html"
    assert enqueue_discovered_url(
        f"{base}?sendAmount=1",
        discovered,
        queue,
        "out.txt",
        log.append,
        stats=stats,
        query_tracker=tracker,
        skip_static_pages=True,
        start_url="https://ex.com/",
    )
    assert enqueue_discovered_url(
        f"{base}?sendAmount=2",
        discovered,
        queue,
        "out.txt",
        log.append,
        stats=stats,
        query_tracker=tracker,
        skip_static_pages=True,
        start_url="https://ex.com/",
    )
    assert not enqueue_discovered_url(
        f"{base}?sendAmount=3",
        discovered,
        queue,
        "out.txt",
        log.append,
        stats=stats,
        query_tracker=tracker,
        skip_static_pages=True,
        start_url="https://ex.com/",
    )
    assert stats.query_variants_skipped >= 1
    assert not enqueue_discovered_url(
        "https://ex.com/staticassets/css/x.css",
        discovered,
        queue,
        "out.txt",
        log.append,
        stats=stats,
        skip_static_pages=True,
        start_url="https://ex.com/",
    )
    assert stats.static_assets_recorded >= 1
    assert "https://ex.com/staticassets/css/x.css" not in queue


def test_exact_origin_scope():
    assert host_in_exact_origin_scope(
        "https://www.example.com/a", "https://www.example.com/"
    )
    assert not host_in_exact_origin_scope(
        "https://www2.example.com/a", "https://www.example.com/"
    )
    discovered = set()
    queue = []
    stats = CrawlStats()
    assert not enqueue_discovered_url(
        "https://www2.example.com/x",
        discovered,
        queue,
        "out.txt",
        lambda *_: None,
        stats=stats,
        start_url="https://www.example.com/",
        scope_mode="exact-origin",
    )
    assert stats.out_of_scope_skipped >= 1


def test_form_fingerprint_ignores_csrf_values_and_skips_js_action():
    html = """
    <form method="post" action="javascript:void(0);">
      <input name="q" type="text"/>
    </form>
    <form method="get" action="/search" enctype="application/x-www-form-urlencoded">
      <input name="q" type="text"/>
      <input name="csrf_token" type="hidden" value="AAA"/>
    </form>
    <form method="get" action="/search">
      <input name="q" type="text"/>
      <input name="csrf_token" type="hidden" value="BBB"/>
    </form>
    """
    forms = extract_forms(html, "https://ex.com/page", "text/html")
    assert all("javascript" not in (f.get("action") or "").lower() for f in forms)
    assert len(forms) == 2
    assert forms[0]["form_key"] == forms[1]["form_key"]
    key = form_fingerprint(
        method="GET",
        action="https://ex.com/search",
        fields=[("q", "text"), ("csrf_token", "hidden")],
        enctype="",
    )
    assert forms[0]["form_key"] == key


def test_directory_base_url():
    from enum_engine import directory_base_url

    assert directory_base_url("https://ex.com/app/", ["admin"]) == "https://ex.com/app/admin/"
    assert directory_base_url("https://ex.com/index.html", []).endswith("/")

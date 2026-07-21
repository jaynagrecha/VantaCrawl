import asyncio
from unittest.mock import AsyncMock, MagicMock

from api_recon.active import run_active_api_enum
from api_recon.imports import load_har_file, load_postman_collection
from api_recon.passive import classify_discovered_urls, extract_from_text
from api_recon.auth import build_api_headers
from crawl_stats import CrawlStats


def test_passive_extract_from_js():
    html = """
    fetch('/api/v1/users')
    axios.get("https://example.com/api/orders")
    const x = '/graphql';
    """
    eps = extract_from_text(html, "https://example.com/")
    paths = {e.path for e in eps}
    assert "/api/v1/users" in paths
    assert any("orders" in e.path for e in eps)
    assert any("graphql" in e.path for e in eps)


def test_classify_discovered_urls():
    eps = classify_discovered_urls(
        [
            "https://example.com/api/health",
            "https://example.com/about",
            "https://example.com/v2/items",
        ]
    )
    urls = {e.url for e in eps}
    assert "https://example.com/api/health" in urls
    assert "https://example.com/v2/items" in urls
    assert "https://example.com/about" not in urls


def test_auth_header():
    h = build_api_headers(header_name="Authorization", header_value="Bearer abc")
    assert h["Authorization"] == "Bearer abc"


def test_postman_import(tmp_path):
    path = tmp_path / "col.json"
    path.write_text(
        """
        {
          "item": [
            {
              "name": "List users",
              "request": {
                "method": "GET",
                "url": "https://example.com/api/users"
              }
            }
          ]
        }
        """,
        encoding="utf-8",
    )
    eps = load_postman_collection(str(path))
    assert len(eps) == 1
    assert eps[0].method == "GET"
    assert "/api/users" in eps[0].path


def test_har_import(tmp_path):
    path = tmp_path / "cap.har"
    path.write_text(
        """
        {
          "log": {
            "entries": [
              {
                "request": {"method": "POST", "url": "https://example.com/api/login"},
                "response": {"status": 200, "content": {"mimeType": "application/json"}}
              },
              {
                "request": {"method": "GET", "url": "https://example.com/index.html"},
                "response": {"status": 200, "content": {"mimeType": "text/html"}}
              }
            ]
          }
        }
        """,
        encoding="utf-8",
    )
    eps = load_har_file(str(path))
    assert len(eps) == 1
    assert eps[0].method == "POST"


def test_note_api_recon_progress_label():
    stats = CrawlStats()
    stats.note_api_recon_progress(10, total=100, path="/api/health", hits=2)
    assert stats.api_recon_probes_done == 10
    assert stats.api_recon_probes_total == 100
    assert stats.api_recon_hits == 2
    label = stats.api_recon_probing_label()
    assert "/api/health" in label
    assert "10" in label and "100" in label
    snap = stats.snapshot()
    assert snap["api_recon_current_path"] == "/api/health"
    assert snap["api_recon_probes_done"] == 10


def test_active_enum_updates_stats(tmp_path):
    wl = tmp_path / "api.txt"
    wl.write_text("health\nusers\n", encoding="utf-8")

    class _Resp:
        def __init__(self, code):
            self.status_code = code
            self.headers = {"content-type": "application/json"}

    client = MagicMock()
    client.head = AsyncMock(return_value=_Resp(404))
    client.get = AsyncMock(return_value=_Resp(404))

    stats = CrawlStats()
    progress = []

    def on_progress(total, done, text):
        progress.append((total, done, text))

    hits = asyncio.run(
        run_active_api_enum(
            client,
            "https://example.com/",
            wordlist_file=str(wl),
            word_limit=8,
            headers={},
            concurrency=2,
            method="HEAD",
            update_progress=on_progress,
            stats=stats,
        )
    )
    assert hits == []
    assert stats.api_recon_probes_total >= 1
    assert stats.api_recon_probes_done == stats.api_recon_probes_total
    assert progress
    assert any("API recon" in str(p[2]) for p in progress)

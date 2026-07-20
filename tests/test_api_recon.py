from api_recon.imports import load_har_file, load_postman_collection
from api_recon.passive import classify_discovered_urls, extract_from_text
from api_recon.auth import build_api_headers


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

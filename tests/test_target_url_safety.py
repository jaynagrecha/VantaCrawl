"""SSRF / private-target guard tests."""

from __future__ import annotations

import ipaddress

import pytest

from target_url_safety import validate_public_http_url, validate_public_http_urls


def test_blocks_localhost():
    with pytest.raises(ValueError, match="not allowed|blocked"):
        validate_public_http_url("http://localhost/admin")
    with pytest.raises(ValueError):
        validate_public_http_url("http://127.0.0.1/")


def test_blocks_metadata_ip():
    with pytest.raises(ValueError, match="blocked"):
        validate_public_http_url("http://169.254.169.254/latest/meta-data/")


def test_blocks_private_literal():
    with pytest.raises(ValueError):
        validate_public_http_url("http://10.0.0.5/internal")
    with pytest.raises(ValueError):
        validate_public_http_url("http://192.168.1.1/")


def test_allows_public_example(monkeypatch):
    def fake_resolve(host):
        return [ipaddress.ip_address("93.184.216.34")]

    monkeypatch.setattr("target_url_safety._resolve_ips", fake_resolve)
    assert validate_public_http_url("https://example.com/path") == "https://example.com/path"


def test_validate_list(monkeypatch):
    def fake_resolve(host):
        return [ipaddress.ip_address("1.1.1.1")]

    monkeypatch.setattr("target_url_safety._resolve_ips", fake_resolve)
    out = validate_public_http_urls(["https://one.example/", "", "https://two.example/"])
    assert len(out) == 2


def test_chrome_probe_cache(monkeypatch):
    from browser_fetch import probe_chrome, reset_chrome_probe_cache

    reset_chrome_probe_cache()
    monkeypatch.setattr("browser_fetch._candidate_chrome_bins", lambda: [])
    ok, detail = probe_chrome()
    assert ok is False
    assert "not found" in detail.lower()
    # cached
    assert probe_chrome()[0] is False
    reset_chrome_probe_cache()

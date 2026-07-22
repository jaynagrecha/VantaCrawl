"""Production bootstrap secret checks."""

from __future__ import annotations

import pytest

from vantacrawl_api.bootstrap import ensure_production_secrets
from vantacrawl_api.config import get_settings


def test_production_rejects_default_secret(monkeypatch):
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("SECRET_KEY", "change-me-in-production-use-long-random-string")
    get_settings.cache_clear()
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        ensure_production_secrets()
    get_settings.cache_clear()
    monkeypatch.delenv("RENDER", raising=False)


def test_dev_allows_default_secret(monkeypatch):
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.delenv("RENDER_SERVICE_ID", raising=False)
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("SECRET_KEY", "change-me-in-production-use-long-random-string")
    get_settings.cache_clear()
    ensure_production_secrets()  # should not raise
    get_settings.cache_clear()

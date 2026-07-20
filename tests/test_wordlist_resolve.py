"""Catalog wordlists must survive ephemeral job uploads/ wipe."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "web" / "api"
if str(API) not in sys.path:
    sys.path.insert(0, str(API))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vantacrawl_api.scan_settings import (  # noqa: E402
    available_wordlists,
    ensure_wordlist_path,
    resolve_catalog_wordlist,
)


def test_catalog_wordlists_exist():
    lists = available_wordlists()
    assert lists
    assert all(Path(w["path"]).is_file() for w in lists)


def test_ensure_rebinds_stale_uploads_path():
    lists = available_wordlists()
    sample = next(w for w in lists if "directory-list" in w["id"] or w["id"].endswith(".txt"))
    stale = f"/opt/render/project/src/web/data/jobs/fake-id/uploads/{sample['id']}"
    resolved = ensure_wordlist_path({"wordlist_file": stale, "wordlist_id": sample["id"]})
    assert Path(resolved).is_file()
    assert "uploads" not in resolved.replace("\\", "/")
    assert Path(resolved).name == sample["id"]


def test_resolve_catalog_by_id():
    lists = available_wordlists()
    sample = lists[0]
    assert resolve_catalog_wordlist(sample["id"]) == sample["path"]
    assert resolve_catalog_wordlist("__upload__") is None

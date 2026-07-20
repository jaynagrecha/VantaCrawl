"""Import endpoints from Postman collections and HAR files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List
from urllib.parse import urlparse

from .models import ApiEndpoint


def _walk_postman_items(items: List[Any], out: List[ApiEndpoint]) -> None:
    for item in items or []:
        if not isinstance(item, dict):
            continue
        if "item" in item:
            _walk_postman_items(item.get("item") or [], out)
            continue
        req = item.get("request")
        if not isinstance(req, dict):
            continue
        method = str(req.get("method") or "GET").upper()
        url_obj = req.get("url")
        raw = ""
        if isinstance(url_obj, str):
            raw = url_obj
        elif isinstance(url_obj, dict):
            raw = str(url_obj.get("raw") or "")
            if not raw:
                host = url_obj.get("host") or []
                path = url_obj.get("path") or []
                if isinstance(host, list):
                    host_s = ".".join(str(h) for h in host)
                else:
                    host_s = str(host)
                if isinstance(path, list):
                    path_s = "/".join(str(p) for p in path)
                else:
                    path_s = str(path)
                proto = str(url_obj.get("protocol") or "https")
                raw = f"{proto}://{host_s}/{path_s}".replace("///", "//")
        if not raw:
            continue
        parsed = urlparse(raw)
        out.append(
            ApiEndpoint(
                method=method,
                url=raw.split("#", 1)[0],
                path=parsed.path or "/",
                source="postman",
                note=str(item.get("name") or "")[:120],
            )
        )


def load_postman_collection(path: str) -> List[ApiEndpoint]:
    p = Path(path)
    if not p.is_file():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    out: List[ApiEndpoint] = []
    _walk_postman_items(data.get("item") or [], out)
    return out


def load_har_file(path: str) -> List[ApiEndpoint]:
    p = Path(path)
    if not p.is_file():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    entries = ((data.get("log") or {}).get("entries")) or []
    out: List[ApiEndpoint] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        req = entry.get("request") or {}
        url = str(req.get("url") or "")
        if not url:
            continue
        method = str(req.get("method") or "GET").upper()
        parsed = urlparse(url)
        path_l = (parsed.path or "").lower()
        # Keep API-ish or all XHR-looking JSON responses
        resp = entry.get("response") or {}
        mime = str(((resp.get("content") or {}).get("mimeType")) or "").lower()
        if not any(x in path_l for x in ("/api", "/v1", "/v2", "/v3", "/graphql", "/rest")) and "json" not in mime:
            continue
        out.append(
            ApiEndpoint(
                method=method,
                url=url.split("#", 1)[0],
                path=parsed.path or "/",
                source="har",
                status=int(resp.get("status") or 0),
                content_type=mime,
            )
        )
    return out

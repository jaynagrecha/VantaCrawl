"""Content-type and URL heuristics to skip low-value downloads."""

from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse

TRACKING_PATH_RE = (
    "pixel", "tracking", "analytics", "beacon", "spacer", "1x1",
    "facebook.com/tr", "doubleclick", "googletagmanager",
)

DEFAULT_SKIP_CONTENT_TYPES = frozenset({
    "image/gif",
    "image/x-icon",
    "application/octet-stream",
})


def should_skip_download(url: str, content_type: str, body_size: int, config) -> Optional[str]:
    if not getattr(config, "skip_tracking_downloads", True):
        return None
    content_type = (content_type or "").lower().split(";")[0].strip()
    blocked = set(getattr(config, "blocked_content_types", []) or [])
    blocked |= DEFAULT_SKIP_CONTENT_TYPES
    if content_type in blocked:
        return f"content-type {content_type}"
    path = urlparse(url).path.lower()
    if any(token in path for token in TRACKING_PATH_RE):
        return "tracking URL pattern"
    if content_type.startswith("image/") and body_size < 512:
        return "tiny image (likely tracker)"
    return None

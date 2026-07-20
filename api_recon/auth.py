from __future__ import annotations

from typing import Dict


def build_api_headers(
    *,
    header_name: str = "Authorization",
    header_value: str = "",
    base_headers: Dict[str, str] | None = None,
) -> Dict[str, str]:
    headers = dict(base_headers or {})
    name = (header_name or "Authorization").strip()
    value = (header_value or "").strip()
    if name and value:
        headers[name] = value
    return headers

"""Lightweight GraphQL introspection."""

from __future__ import annotations

from typing import Dict, List, Tuple
from urllib.parse import urlparse

import httpx

from .models import ApiEndpoint

_INTROSPECTION = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          kind
          name
          fields {
            name
          }
        }
      }
    }
    """
}


async def try_introspection(
    client: httpx.AsyncClient,
    url: str,
    *,
    headers: dict,
) -> Tuple[List[Dict[str, str]], List[ApiEndpoint]]:
    ops: List[Dict[str, str]] = []
    endpoints: List[ApiEndpoint] = []
    try:
        resp = await client.post(url, json=_INTROSPECTION, headers=headers, timeout=15, follow_redirects=True)
    except httpx.HTTPError:
        return ops, endpoints
    endpoints.append(
        ApiEndpoint(
            method="POST",
            url=str(resp.url),
            path=urlparse(str(resp.url)).path or "/graphql",
            source="graphql",
            status=resp.status_code,
            content_type=(resp.headers.get("content-type") or "")[:80],
            note="Introspection probe",
        )
    )
    try:
        data = resp.json()
    except Exception:
        return ops, endpoints
    schema = ((data.get("data") or {}).get("__schema")) or {}
    if not schema:
        return ops, endpoints
    for t in schema.get("types") or []:
        if not isinstance(t, dict):
            continue
        if t.get("kind") != "OBJECT":
            continue
        name = str(t.get("name") or "")
        if name.startswith("__"):
            continue
        for field in t.get("fields") or []:
            if not isinstance(field, dict):
                continue
            fname = str(field.get("name") or "")
            if not fname:
                continue
            ops.append({"type": name, "field": fname})
            if len(ops) >= 400:
                return ops, endpoints
    return ops, endpoints

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ApiEndpoint:
    method: str
    url: str
    path: str
    source: str
    status: int = 0
    content_type: str = ""
    note: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {
            "method": self.method,
            "url": self.url,
            "path": self.path,
            "source": self.source,
            "status": self.status,
            "content_type": self.content_type,
            "note": self.note,
        }


@dataclass
class ApiReconResult:
    endpoints: List[ApiEndpoint] = field(default_factory=list)
    docs: List[str] = field(default_factory=list)
    graphql_operations: List[Dict[str, str]] = field(default_factory=list)
    probed: int = 0
    hits: int = 0

    def dedupe_endpoints(self) -> None:
        seen = set()
        unique: List[ApiEndpoint] = []
        for ep in self.endpoints:
            key = (ep.method.upper(), ep.url.rstrip("/"))
            if key in seen:
                continue
            seen.add(key)
            unique.append(ep)
        self.endpoints = unique

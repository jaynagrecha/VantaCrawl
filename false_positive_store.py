"""Persist learned false-positive fingerprints between runs."""

from __future__ import annotations

import json
import os
from typing import Iterable, Set, Tuple
from urllib.parse import urlparse

Signature = Tuple[int, int, str]
HostSignature = Tuple[str, int, int, str]


def _host_of(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


class FalsePositiveStore:
    def __init__(self, path: str):
        self.path = path
        self.signatures: Set[Signature] = set()
        self.host_signatures: Set[HostSignature] = set()
        self.urls: Set[str] = set()

    def load(self):
        if not self.path or not os.path.isfile(self.path):
            return
        try:
            with open(self.path, encoding="utf-8") as handle:
                data = json.load(handle)
            for item in data.get("signatures", []):
                if len(item) == 3:
                    self.signatures.add((int(item[0]), int(item[1]), str(item[2])))
                elif len(item) == 4:
                    self.host_signatures.add((str(item[0]), int(item[1]), int(item[2]), str(item[3])))
            for item in data.get("host_signatures", []):
                if len(item) == 4:
                    self.host_signatures.add((str(item[0]), int(item[1]), int(item[2]), str(item[3])))
            self.urls.update(data.get("urls", []))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            pass

    def save(self):
        if not self.path:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self.path)) or ".", exist_ok=True)
        payload = {
            "signatures": [list(item) for item in sorted(self.signatures)],
            "host_signatures": [list(item) for item in sorted(self.host_signatures)],
            "urls": sorted(self.urls),
        }
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        os.replace(tmp, self.path)

    def is_false_positive(self, status: int, content_length: int, body_hash: str, url: str = "") -> bool:
        if url and url in self.urls:
            return True
        host = _host_of(url)
        if host and (host, status, content_length, body_hash) in self.host_signatures:
            return True
        # Legacy global signatures only apply when hash is concrete (not head-only)
        if body_hash and body_hash != "head-only" and (status, content_length, body_hash) in self.signatures:
            return True
        return False

    def record(self, status: int, content_length: int, body_hash: str, url: str = ""):
        host = _host_of(url)
        if host and body_hash and body_hash != "head-only":
            self.host_signatures.add((host, status, content_length, body_hash))
        elif body_hash and body_hash != "head-only":
            self.signatures.add((status, content_length, body_hash))
        if url:
            self.urls.add(url)

    def record_url_only(self, url: str):
        if url:
            self.urls.add(url)

    def record_many(self, items: Iterable[Signature]):
        self.signatures.update(items)
